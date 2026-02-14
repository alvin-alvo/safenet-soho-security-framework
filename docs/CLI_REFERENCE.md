# SafeNet CLI Reference

The CLI is built with `typer` and `rich` for a modern terminal experience.

> [!IMPORTANT]
> **Administrator Privileges Required**
> You must run your terminal (PowerShell or CMD) as **Administrator** to execute these commands, as they interact with the Windows Service Manager and Network Adapters.

## Usage
Run commands from the project root using the virtual environment:
```powershell
python cli/console.py [COMMAND] [ARGS]
```

## Commands

### `status`
Check the health of the API server and the WireGuard tunnel.
```powershell
python cli/console.py status
```
**Output**: 
- API: Healthy/Unreachable
- Gateway: Online/Offline

### `start`
Start the WireGuard tunnel service. **Requires Administrator Privileges.**
```powershell
python cli/console.py start
```

### `stop`
Stop the tunnel and clear server keys from memory.
```powershell
python cli/console.py stop
```

### `list`
List all enrolled devices with real-time connection stats.
```powershell
python cli/console.py list
```
**Fields**: Name, IP, Public Key, Status (Active/Offline), Data Transfer (Rx/Tx).

### `enroll <device_name>`
Provision a new device.
```powershell
python cli/console.py enroll my-iphone
```
**Output**:
- Generates keys.
- Assigns IP.
-Displays QR Code for scanning.
- Saves `.conf` file to `wg_configs/`.

### `remove <device_name>`
Revoke access for a device.
```powershell
python cli/console.py remove my-iphone
```
**Effect**: 
- Immediately hot-reloads the server to drop the peer connection.
