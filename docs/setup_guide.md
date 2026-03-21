# Windows Gateway Setup Guide

Deploying Project SafeNet on a Windows Server or SOHO Windows 10/11 instance requires specific elevated configurations to allow kernel-space routing and firewall traversal.

> **Warning:** You must have Administrator privileges to successfully execute this setup.

## Step 1: Framework Installation
Clone the repository and run the setup wizard to create the Python virtual environment and install dependencies.

```bat
git clone https://github.com/your-org/safenet-soho-security-framework.git
cd safenet-soho-security-framework
setup_env.bat
```

## Step 2: Enable IP Forwarding
By default, Windows aggressively drops packets not destined for its own IP stack. For the WireGuard vNIC to route traffic from peers (even if just to the gateway itself via the tunnel), you must enable IP Forwarding in the registry.

Open an Administrator PowerShell and run:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
```

*Note: You must restart the machine for this registry key to take effect.*

## Step 3: Windows Firewall Traversal (UDP 65065)
WireGuardNT listens on a specific UDP port defined in the configuration. The default for SafeNet is `65065`. You must create an explicit inbound rule to allow external handshake packets to reach the kernel mechanism.

Open an Administrator PowerShell and run:
```powershell
New-NetFirewallRule -DisplayName "SafeNet_WireGuard_UDP_65065" -Direction Inbound -Subnet Any -Action Allow -Protocol UDP -LocalPort 65065
```

## Step 4: Launching the Server
With dependencies installed, routing enabled, and the firewall explicitly opened, you can spin up the gateway.

Right-click `run_server.bat` and select **Run as Administrator**.
*(Administrator privileges are strictly required to create the `safenet0` network interface and inject kernel-space routing rules).*

You can now navigate to `http://localhost:8000/docs` to interact with the API.
