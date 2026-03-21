# Security Model & Threat Landscape

Project SafeNet enforces Zero-Trust principles natively at Layer 3 using deterministic cryptographic proofs.

## Core Thesis: /32 Cryptokey Routing
Traditional VPNs authorize access to entire subnets (e.g., `10.8.0.0/24`), relying on complex and often misconfigured firewall rules (iptables/netsh) to manage micro-segmentation. This inherent flaw enables lateral movement once an attacker breaches a single peer.

SafeNet utilizes WireGuard's **Cryptokey Routing** primitive, specifically constrained to **`/32` allocations**.

### How It Works
1. Every peer is assigned a single `/32` IP address (e.g., `10.8.0.5/32`) and a unique Curve25519 Public Key.
2. The Hub's interface maps the specific Public Key **strictly** to that `/32` IP in its `AllowedIPs` table.
3. When a packet arrives, WireGuard checks the cryptographic signature of the packet against the inner IP header.
4. **The Mathematical Block:** If Peer A (`10.8.0.5/32`) attempts to send a packet with a spoofed source IP claiming to be Peer B (`10.8.0.6/32`), WireGuard drops the packet immediately in kernel space. There is no firewall rule to misconfigure; the packet fails the cryptographic validation tied to the routing table.

### Strict Isolation
By default, the Windows Gateway does not route packets *between* peers. All peers can only communicate directly with the Gateway application services themselves (or external internet if explicitly routed). Lateral movement (Peer A -> Peer B) is blocked natively.

## Threat Model

### What We Protect Against
- **Network Spoofing:** Dropped mathematically by Cryptokey routing.
- **Lateral Movement:** Blocked by strict `/32` isolation and lack of peer-to-peer forwarding.
- **Unauthorized Enrollment:** FastAPI endpoint is protected via JWT Authorization; unauthorized devices cannot be added to the SQLite DB or WireGuard interface.
- **Replay Attacks:** Handled natively by WireGuard's monotonically increasing time-stamped nonces.
- **Man-in-the-Middle (MitM):** Prevented by Noise Protocol Framework (Curve25519, ChaCha20, Poly1305).

### Layer 7 Limitations (Current State)
SafeNet operates fundamentally at Layer 3 (Network Layer).
- **No Deep Packet Inspection (DPI):** SafeNet cannot inspect the contents of HTTP/HTTPS traffic inside the tunnel.
- **No Native IDS/IPS:** It cannot detect malicious SQL injection or malware payloads if the peer is authorized to communicate with a target service.
- **Application Level Vulnerabilities:** If a service exposed on the Gateway has an unpatched vulnerability, SafeNet cannot prevent an authorized peer from exploiting it.

Future iterations aim to bridge this gap via endpoint eBPF agents or integrating a lightweight SIEM/IDS hook on the Gateway's vNIC.
