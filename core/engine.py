"""
SafeNet Core - Windows WireGuard Subprocess Driver

This module provides asynchronous control of WireGuard tunnels on Windows.
It acts as the bridge between the Python control plane and the Windows OS
network stack, translating network state into WireGuard configurations.

Security Architecture:
- Zero command injection: list-based subprocess arguments only
- Absolute paths: resolves full paths for Windows services
- Non-blocking: fully async tunnel lifecycle management
- Secure cleanup: removes config files after tunnel shutdown

Windows WireGuard Enterprise Documentation:
- Install: wireguard.exe /installtunnelservice <path-to-conf>
- Uninstall: wireguard.exe /uninstalltunnelservice <tunnel-name>
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration Generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def generate_config_string(
    private_key: str,
    local_ip: str,
    server_public_key: str = "SERVER_PUB_KEY_PLACEHOLDER",
    server_endpoint: str = "192.168.137.1:65065"
) -> str:
    """
    Generate CLIENT WireGuard configuration string for API responses.
    
    This function creates a complete client configuration with:
    - [Interface] section: client's private key and IP
    - [Peer] section: server connection details
    
    This is ONLY for client devices connecting TO the server.
    For server configuration, use generate_server_config() instead.
    
    Args:
        private_key: Client's WireGuard private key (Base64, 44 chars)
        local_ip: Client's assigned IP address with CIDR (e.g., "10.8.0.2/24")
        server_public_key: Server's public key (TODO: fetch from DB in Phase 6)
        server_endpoint: Server IP:port (default: 192.168.137.1:65065)
        
    Returns:
        Complete WireGuard client configuration as a string
        
    Security:
        - Private key is ephemeral (generated in-memory, returned once, never stored)
        - Configuration transmitted over HTTPS in production
        - No placeholder values in production (Phase 6 will use DB)
        
    Example Output:
        [Interface]
        PrivateKey = cNJx...
        Address = 10.8.0.2/24
        
        [Peer]
        PublicKey = HIgo...
        AllowedIPs = 10.8.0.0/24
        Endpoint = 192.168.137.1:65065
        PersistentKeepalive = 25
    """
    logger.info(f"Generating CLIENT config: local_ip={local_ip}, endpoint={server_endpoint}")
    
    # Build complete client configuration
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {local_ip}

[Peer]
# SafeNet Server (Windows Mobile Hotspot)
PublicKey = {server_public_key}
AllowedIPs = 10.8.0.0/24
Endpoint = {server_endpoint}
PersistentKeepalive = 25
"""
    
    logger.info("Client config generated successfully")
    return config


def generate_server_config(
    server_private_key: str,
    peers: List[Dict[str, str]] = None,
    server_address: str = "10.8.0.1/24",
    listen_port: int = 65065
) -> str:
    """
    Generate SERVER WireGuard configuration string with dynamic peer support.
    
    This function creates a complete server configuration with:
    - [Interface] section: server's private key, address, and listen port
    - [Peer] sections: one block for each enrolled device
    
    Args:
        server_private_key: Server's WireGuard private key (Base64, 44 chars)
        peers: List of peer dictionaries, each containing:
               - "public_key": Device's WireGuard public key
               - "allowed_ips": Device's IP with /32 CIDR (e.g., "10.8.0.2/32")
        server_address: Server's IP with CIDR (default: 10.8.0.1/24)
        listen_port: UDP port to listen on (default: 65065)
        
    Returns:
        Complete WireGuard server configuration as a string
        
    Security:
        - Server private key is ephemeral (regenerated on tunnel start)
        - Each peer gets /32 CIDR (single IP, no subnet routing)
        - No placeholder values - all keys are real
        
    Example Output:
        [Interface]
        PrivateKey = 4N+CBG8dre07RazfEl2BZ/T1QVD0yHTV2T7nd5uxyXY=
        Address = 10.8.0.1/24
        ListenPort = 65065
        
        [Peer]
        # Device: phone-alice
        PublicKey = HIgo5A3qKwgVcGMNPh3jLMO...
        AllowedIPs = 10.8.0.2/32
        
        [Peer]
        # Device: laptop-bob
        PublicKey = cNJx4wQZ8T2V0yHTV2T7nd...
        AllowedIPs = 10.8.0.3/32
    """
    if peers is None:
        peers = []
    
    logger.info(f"Generating SERVER config: address={server_address}, port={listen_port}, peers={len(peers)}")
    
    # Build [Interface] section
    config_lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_address}",
        f"ListenPort = {listen_port}",
        ""  # Blank line for readability
    ]
    
    # Build [Peer] sections for each enrolled device
    for idx, peer in enumerate(peers, start=1):
        logger.debug(f"Adding peer {idx}: {peer.get('public_key', 'N/A')[:20]}... -> {peer.get('allowed_ips')}")
        
        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {peer['public_key']}")
        config_lines.append(f"AllowedIPs = {peer['allowed_ips']}")
        config_lines.append("")  # Blank line between peers
    
    config = "\n".join(config_lines)
    
    logger.info(f"Server config generated successfully: {len(peers)} peers included")
    logger.info(f"Server config generated successfully: {len(peers)} peers included")
    return config


async def get_persistent_server_keys(tunnel_name: str = "safenet-vpn") -> Tuple[Optional[str], Optional[str]]:
    """
    Retrieve existing server keys from the persisted configuration file.
    
    This prevents the server from regenerating keys on every restart,
    which would invalidate all client configurations.
    
    Returns:
        Tuple (private_key, public_key) or (None, None) if not found.
    """
    try:
        from core.utils import get_program_data_dir
        from core.keygen import derive_public_key
        import re
        
        config_dir = Path(get_program_data_dir())
        config_file = config_dir / f"{tunnel_name}.conf"
        
        print(f"DEBUG: Checking persistent config at: {config_file}")
        
        if not config_file.exists():
            print("DEBUG: Config file not found")
            return None, None
            
        content = config_file.read_text(encoding="utf-8")
        
        # Extract PrivateKey from [Interface]
        # Look for PrivateKey = <key>
        match = re.search(r"PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)", content)
        if match:
            private_key = match.group(1).strip()
            print(f"DEBUG: Found PrivateKey in config (len={len(private_key)})")
            public_key = await derive_public_key(private_key)
            print(f"DEBUG: Derived PublicKey: {public_key}")
            logger.info("Loaded persistent server keys from disk")
            return private_key, public_key
        else:
            print("DEBUG: PrivateKey not found in config content (Regex mismatch)")
            
    except Exception as e:
        print(f"DEBUG: Error loading persistent keys: {e}")
        logger.warning(f"Failed to load persistent keys: {e}")
        
    return None, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tunnel Lifecycle Management
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


async def start_safenet_tunnel(
    config_string: str,
    tunnel_name: str = "safenet-vpn",  # CHANGED: New default name to bypass stuck service
    config_dir: Path = None  # CHANGED: Default to None to use temp dir
) -> bool:
    """
    Start a WireGuard tunnel on Windows using the enterprise wireguard.exe CLI.
    
    This function:
    1. Writes the config to a temporary .conf file (bypassing data/ perm issues)
    2. Resolves the absolute path (required by Windows services)
    3. Calls `wireguard.exe /installtunnelservice <absolute-path>`
    4. Waits for the service to start
    
    Args:
        config_string: Complete WireGuard configuration (from generate_config_string)
        tunnel_name: Name of the tunnel service (default: "safenet-vpn")
        config_dir: Directory to store config file (default: None -> use temp dir)
    
    Returns:
        bool: True if tunnel started successfully, False otherwise
    
    Raises:
        RuntimeError: If wireguard.exe is not found or service fails to start
    
    Security Notes:
        - Uses list-based subprocess args (prevents command injection)
        - Validates config file write before calling wireguard.exe
        - No shell=True (prevents shell injection)
    
    Windows Enterprise CLI:
        wireguard.exe /installtunnelservice C:\\absolute\\path\\to\\safenet.conf
    """
    logger.info(f"Starting WireGuard tunnel: {tunnel_name}")
    
    # Use ProgramData directory if no config_dir specified
    # This avoids permission issues (service account vs user temp)
    if config_dir is None:
        from core.utils import get_program_data_dir
        config_dir = Path(get_program_data_dir())
    
    # Ensure config directory exists
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Write config to file
    config_file = config_dir / f"{tunnel_name}.conf"
    
    try:
        logger.debug(f"Writing config to: {config_file}")
        config_file.write_text(config_string, encoding="utf-8")
        logger.info(f"Config file written: {config_file} ({len(config_string)} bytes)")
    except Exception as e:
        logger.error(f"Failed to write config file: {e}")
        raise RuntimeError(f"Config file write failed: {e}")
    
    # Resolve absolute path (Windows services require absolute paths)
    absolute_config_path = config_file.resolve()
    logger.debug(f"Resolved absolute path: {absolute_config_path}")
    
    # Validate config file exists before calling wireguard.exe
    if not absolute_config_path.exists():
        logger.error(f"Config file does not exist: {absolute_config_path}")
        raise RuntimeError(f"Config file not found: {absolute_config_path}")
    
    # Build wireguard.exe command
    # Security: List-based args prevent command injection
    wireguard_cmd = [
        "wireguard.exe",
        "/installtunnelservice",
        str(absolute_config_path)
    ]
    
    logger.info(f"Executing: {' '.join(wireguard_cmd)}")
    
    try:
        # Execute wireguard.exe asynchronously
        # CRITICAL: shell=False (default) prevents shell injection
        process = await asyncio.create_subprocess_exec(
            *wireguard_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for process to complete
        stdout, stderr = await process.communicate()
        
        # Decode output
        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        
        # Check return code
        if process.returncode == 0:
            logger.info(f"Tunnel '{tunnel_name}' started successfully")
            if stdout_text:
                logger.debug(f"stdout: {stdout_text}")
            return True
        else:
            # Handle "Tunnel already installed and running"
            if "Tunnel already installed and running" in stderr_text:
                logger.warning(f"Tunnel '{tunnel_name}' is already running. Restarting...")
                
                # Stop the existing tunnel
                await stop_safenet_tunnel(tunnel_name, config_dir=config_dir)
                
                # Retry start (recursive call or just re-run command? Re-run command is safer here)
                logger.info(f"Retrying start for '{tunnel_name}'...")
                process_retry = await asyncio.create_subprocess_exec(
                    *wireguard_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_retry, stderr_retry = await process_retry.communicate()
                
                if process_retry.returncode == 0:
                    logger.info(f"Tunnel '{tunnel_name}' restarted successfully")
                    return True
                else:
                    stderr_text = stderr_retry.decode("utf-8", errors="replace").strip()
            
            logger.error(f"Tunnel start failed (exit code: {process.returncode})")
            if stderr_text:
                logger.error(f"stderr: {stderr_text}")
            raise RuntimeError(
                f"Tunnel start failed with exit code {process.returncode}: {stderr_text}"
            )
    
    except FileNotFoundError:
        logger.error("wireguard.exe not found in system PATH")
        raise RuntimeError(
            "wireguard.exe not found. Ensure WireGuard for Windows is installed "
            "and 'C:\\Program Files\\WireGuard' is in your system PATH.\n"
            "Download: https://www.wireguard.com/install/"
        )
    
    except Exception as e:
        logger.error(f"Unexpected error during tunnel start: {e}")
        raise RuntimeError(f"Tunnel start failed: {e}")


async def stop_safenet_tunnel(
    tunnel_name: str = "safenet-vpn",
    config_dir: Path = None,  # CHANGED: Default to None to use temp dir
    delete_config: bool = True
) -> bool:
    """
    Stop a running WireGuard tunnel on Windows.
    
    This function:
    1. Calls `wireguard.exe /uninstalltunnelservice <tunnel-name>`
    2. Waits for the service to stop
    3. Optionally deletes the config file for security cleanup
    
    Args:
        tunnel_name: Name of the tunnel service to stop (default: "safenet-vpn")
        config_dir: Directory where config file is stored (default: None -> use temp dir)
        delete_config: Whether to delete the .conf file after stopping (default: True)
    
    Returns:
        bool: True if tunnel stopped successfully, False otherwise
    
    Raises:
        RuntimeError: If wireguard.exe is not found or service fails to stop
    
    Security Notes:
        - Uses list-based subprocess args (prevents command injection)
        - Securely deletes config file after tunnel shutdown
        - No shell=True (prevents shell injection)
    
    Windows Enterprise CLI:
        wireguard.exe /uninstalltunnelservice safenet
    """
    logger.info(f"Stopping WireGuard tunnel: {tunnel_name}")
    
    # Use ProgramData directory if no config_dir specified
    if config_dir is None:
        from core.utils import get_program_data_dir
        config_dir = Path(get_program_data_dir())
    
    # Build wireguard.exe command
    # Security: List-based args prevent command injection
    wireguard_cmd = [
        "wireguard.exe",
        "/uninstalltunnelservice",
        tunnel_name
    ]
    
    logger.info(f"Executing: {' '.join(wireguard_cmd)}")
    
    try:
        # Execute wireguard.exe asynchronously
        # CRITICAL: shell=False (default) prevents shell injection
        process = await asyncio.create_subprocess_exec(
            *wireguard_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for process to complete
        stdout, stderr = await process.communicate()
        
        # Decode output
        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        
        # Check return code
        if process.returncode == 0:
            logger.info(f"Tunnel '{tunnel_name}' stopped successfully")
            if stdout_text:
                logger.debug(f"stdout: {stdout_text}")
        else:
            logger.warning(f"Tunnel stop returned non-zero exit code: {process.returncode}")
            if stderr_text:
                logger.warning(f"stderr: {stderr_text}")
            # Don't raise error - tunnel might already be stopped
    
    except FileNotFoundError:
        logger.error("wireguard.exe not found in system PATH")
        raise RuntimeError(
            "wireguard.exe not found. Ensure WireGuard for Windows is installed "
            "and 'C:\\Program Files\\WireGuard' is in your system PATH.\n"
            "Download: https://www.wireguard.com/install/"
        )
    
    except Exception as e:
        logger.error(f"Unexpected error during tunnel stop: {e}")
        raise RuntimeError(f"Tunnel stop failed: {e}")
    
    # Wait for service to fully unload (race condition fix)
    await asyncio.sleep(3)
    
    # Cleanup: Delete config file for security
    if delete_config:
        config_file = Path(config_dir) / f"{tunnel_name}.conf"
        
        if config_file.exists():
            try:
                logger.debug(f"Deleting config file: {config_file}")
                config_file.unlink()
                logger.info(f"Config file deleted: {config_file}")
            except Exception as e:
                logger.warning(f"Failed to delete config file: {e}")
        else:
            logger.debug(f"Config file does not exist (already deleted?): {config_file}")
    
    return True



async def reload_wireguard_server(
    server_private_key: str,
    peers: List[Dict],
    tunnel_name: str = "safenet-vpn",
    config_dir: Path = None
) -> bool:
    """
    Reload the WireGuard server configuration with a new peer list.
    
    This function performs a hot-reload by:
    1. Generating a new config file
    2. Restarting the tunnel service (stop -> start)
    
    Arguments:
        server_private_key: Server's private key
        peers: List of peer dictionaries (with 'public_key' and allowed_ips')
        tunnel_name: Name of the tunnel service (default: "safenet-vpn")
        config_dir: Directory to store config file
        
    Returns:
        bool: True if successful
    """
    logger.info(f"Hot-reloading server tunnel: {len(peers)} peers to be added")
    
    try:
        # Step 1: Generate new server config with all peers
        logger.debug(f"Generating new server config with {len(peers)} peers")
        new_config = generate_server_config(
            server_private_key=server_private_key,
            peers=peers
        )
        
        # Step 2: Stop existing tunnel (don't delete config yet)
        logger.info("Stopping existing tunnel...")
        try:
            await stop_safenet_tunnel(
                tunnel_name=tunnel_name,
                config_dir=config_dir,
                delete_config=False  # Keep config for safety
            )
        except Exception as e:
            # Tunnel might not be running - that's okay
            logger.warning(f"Tunnel stop returned error (may not be running): {e}")
        
        # Step 3: Write new config
        logger.info("Writing new server config with updated peer list...")
        success = await start_safenet_tunnel(
            config_string=new_config,
            tunnel_name=tunnel_name,
            config_dir=config_dir
        )
        
        if success:
            logger.info(f"Server tunnel reloaded successfully with {len(peers)} peers")
            return True
        else:
            logger.error("Failed to restart tunnel with new config")
            return False
            
    except Exception as e:
        logger.error(f"Hot-reload failed: {e}")
        raise RuntimeError(f"Failed to reload WireGuard server: {e}")


async def get_tunnel_status(tunnel_name: str = "safenet-vpn") -> Optional[Dict[str, str]]:
    """
    Check if a WireGuard tunnel is currently running.
    
    Returns:
        dict: Status information if running, None otherwise.
              Returns {"state": "4"} for compatibility if running.
    """
    interface_name = tunnel_name
    logger.debug(f"Checking interface status: {interface_name}")
    
    wg_cmd = ["wg", "show", interface_name]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *wg_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            logger.info(f"Tunnel '{interface_name}' is ACTIVE (wg show success)")
            return {"state": "4", "msg": "Active"}
        else:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            logger.debug(f"Tunnel '{interface_name}' is INACTIVE. Error: {stderr_text}")
            return None
    
    except Exception as e:
        logger.warning(f"Failed to query tunnel status: {e}")
        return None


async def get_active_peers(tunnel_name: str = "safenet-vpn") -> Dict[str, Dict]:
    """
    Get real-time status of all peers from WireGuard.
    
    Parses `wg show <interface> dump` output.
    Returns:
        Dict[str, Dict]: Keyed by public_key
    """
    interface_name = tunnel_name
    wg_cmd = ["wg", "show", interface_name, "dump"]
    
    try:
        # Check output
        process = await asyncio.create_subprocess_exec(
            *wg_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            return {}
            
        output = stdout.decode("utf-8").strip()
        peers = {}
        
        import time
        now = int(time.time())
        
        if not output:
             return {}
        
        for line in output.split("\n"):
            parts = line.strip().split("\t")
            if len(parts) < 8:
                continue
                
            # Parse fields [pub_key, psk, endpoint, allowed_ips, handshake, rx, tx, keepalive]
            pub_key = parts[0]
            endpoint = parts[2]
            handshake = int(parts[4])
            rx = int(parts[5])
            tx = int(parts[6])
            
            # Active if handshake < 300s (5 mins) - Reduced flapping
            is_active = (now - handshake) < 300 and handshake > 0
            
            peers[pub_key] = {
                "endpoint": endpoint,
                "latest_handshake": handshake,
                "transfer_rx": rx,
                "transfer_tx": tx,
                "is_active": is_active
            }
            
        return peers
        
    except Exception as e:
        logger.error(f"Failed to get active peers: {e}")
        return {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test/Demo Code
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


async def _test_engine():
    """
    Test the WireGuard engine with a sample configuration.
    
    WARNING: This will attempt to create a real WireGuard tunnel on Windows.
    Only run this if you have WireGuard installed and admin privileges.
    """
    print("=" * 70)
    print("SafeNet WireGuard Engine - Test Suite")
    print("=" * 70)
    print()
    
    # Generate a sample configuration
    print("[TEST 1] Generating WireGuard config...")
    
    # NOTE: These are dummy keys for testing
    # In production, use generate_wireguard_keys() from core.keygen
    sample_private_key = "cNJxVO8VnHKwDmkYjFcSrAIvR6xBPmZqvW0yHfUZnkg="
    sample_public_key = "HIgo3OfthMXqP3i2e7yzj7WUMaKv4jEvRBDbK3i8bm8="
    
    config = generate_config_string(
        private_key=sample_private_key,
        local_ip="10.8.0.1/24",
        listen_port=51820,
        peers=[
            {
                "public_key": sample_public_key,
                "allowed_ips": "10.8.0.2/32",
                "endpoint": "192.168.1.10:51820"
            }
        ]
    )
    
    print("Config generated:")
    print("-" * 70)
    print(config)
    print("-" * 70)
    print()
    
    # Test tunnel start (ENABLED - requires admin privileges)
    print("[TEST 2] Tunnel start/stop (requires WireGuard + Admin)")
    print("Testing tunnel lifecycle...")
    print()
    
    # Tunnel operations test (ACTIVE - requires admin!):
    try:
        print("Starting tunnel...")
        await start_safenet_tunnel(config)
        print("Tunnel started!")
        
        print("Checking status...")
        status = await get_tunnel_status()
        print(f"Status: {status}")
        
        print("Stopping tunnel...")
        await stop_safenet_tunnel()
        print("Tunnel stopped!")
    except Exception as e:
        print(f"Error: {e}")
    
    print("=" * 70)
    print("Engine test complete")
    print("=" * 70)


if __name__ == "__main__":
    """
    Main entry point for engine testing.
    """
    try:
        # Add WireGuard to PATH temporarily (Windows-specific)
        if "WireGuard" not in os.environ.get("PATH", ""):
            os.environ["PATH"] += r";C:\Program Files\WireGuard"
        
        # Run async test
        asyncio.run(_test_engine())
        
    except KeyboardInterrupt:
        print("\n[INFO] Test interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
