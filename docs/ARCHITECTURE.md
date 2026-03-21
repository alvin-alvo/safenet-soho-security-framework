# Architecture Overview

Project SafeNet is designed exclusively around a robust, lightweight **Hub and Spoke** paradigm built for Zero-Trust Network Access (ZTNA) in Small Office / Home Office (SOHO) environments.

![System Architecture](assets/system%20architecture.png)

## Macro-Flow: Hub/Spoke Topology
- **Hub:** The central Windows Server gateway acting as the authoritative routing core. It utilizes WireGuardNT for kernel-space cryptography and routing.
- **Spokes:** The endpoint peers (laptops, mobile devices) connecting exclusively to the Hub.

Safenet strictly forbids mesh networking. All peer traffic must route through the Hub, where it is subjected to granular security policies, authentication, and cryptographic routing.

## Micro-Flow: Decoupled Control & Data Planes
The architecture mathematically decouples the **Control Plane** from the **Data Plane**.

### Control Plane
- **FastAPI:** Handles all HTTPS API requests, JWT authentication, UI interactions, and Peer Enrollment logic.
- **SQLite:** Acts as the persistent source of truth for peer identities, public keys, assigned IPs, and metadata.

### Data Plane
- **WireGuardNT:** Handles the actual packet encryption, decryption, and encapsulation over UDP port 65065.

**The Synchronization Flow:**
1. A peer attempts to enroll via the **FastAPI** endpoint.
2. The FastAPI service provisions a robust cryptographic identity (Public/Private Keys, Preshared Key) and assigns a static /32 IP address.
3. This state is committed to **SQLite**.
4. The system issues a `syncconf` command to the running **WireGuardNT** tunnel, transparently injecting the peer's public key and `AllowedIPs` into the kernel memory.
5. The WireGuard interface hot-reloads without dropping existing connections.

![Data Flow Diagram](assets/data%20flow%20diagram.png)

## Component Interactions
- The UI (CLI or proposed Flutter app) interacts exclusively with the FastAPI layer.
- The FastAPI layer validates intent and modifies SQLite.
- A core synchronization module reads SQLite and enforces the state upon WireGuardNT.

![Sub System Architecture](assets/sub%20system%20architecture.png)
