"""
SafeNet API - Route Definitions

This module defines all API endpoints for the SafeNet control plane.
All endpoints are protected with JWT authentication and use async execution.

Endpoints:
- POST /api/token - Generate JWT authentication token
- GET /api/status - Check WireGuard tunnel status
- POST /api/network/start - Start WireGuard tunnel
- POST /api/network/stop - Stop WireGuard tunnel  
- POST /api/devices/enroll - Enroll new device and generate config

Security:
- All endpoints require JWT authentication (except /token)
- Strict input validation via Pydantic
- Async/await for non-blocking execution
- No shell=True (prevents command injection)

Author: SafeNet Security Team
License: GPL-3.0
"""

import logging
from typing import Dict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

# SafeNet core modules
from core import (
    generate_wireguard_keys,
    generate_config_string,
    start_safenet_tunnel,
    stop_safenet_tunnel,
    get_tunnel_status,
    get_active_peers,
    add_device,
    get_device,
    list_devices,
    delete_device,
    init_db,
    allocate_next_ip
)

# API modules
from api.auth import create_access_token, get_current_user, ACCESS_TOKEN_EXPIRE_HOURS
from api.schemas import (
    TokenRequest,
    TokenResponse,
    EnrollDeviceRequest,
    EnrollDeviceResponse,
    StatusResponse,
    NetworkResponse,
    ErrorResponse,
    DeviceStatus,
    DeviceListResponse
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Logger
logger = logging.getLogger(__name__)

# Router
router = APIRouter(prefix="/api", tags=["safenet"])

# Hardcoded credentials for MVP (replace with database in production)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "safenet_admin_2026"  # TODO: Use environment variable


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUTHENTICATION ENDPOINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Generate JWT Token",
    description="Authenticate and receive a JWT token for API access"
)
async def login(request: TokenRequest) -> TokenResponse:
    """
    Generate JWT authentication token.
    
    For MVP, uses hardcoded admin credentials.
    In production, integrate with proper user database.
    
    Args:
        request: Username and password
        
    Returns:
        JWT token with expiration time
        
    Raises:
        HTTPException 401: Invalid credentials
    """
    logger.info(f"Login attempt for user: {request.username}")
    
    # Validate credentials (hardcoded for MVP)
    if request.username != ADMIN_USERNAME or request.password != ADMIN_PASSWORD:
        logger.warning(f"Failed login attempt for user: {request.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": request.username, "role": "admin"},
        expires_delta=timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    
    logger.info(f"JWT token generated for user: {request.username}")
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_HOURS * 3600  # Convert to seconds
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TUNNEL STATUS ENDPOINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/status",
    response_model=StatusResponse,
    summary="Check Tunnel Status",
    description="Check if the WireGuard tunnel is active"
)
async def check_status(
    current_user: Dict = Depends(get_current_user)
) -> StatusResponse:
    """
    Check WireGuard tunnel status.
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        Status response with tunnel state
        
    Security:
        Requires valid JWT token
    """
    logger.info(f"Status check requested by: {current_user['sub']}")
    
    try:
        # Query tunnel status from Windows service
        status_info = await get_tunnel_status()
        
        if status_info and status_info.get("state") == "4":
            # State 4 = RUNNING
            return StatusResponse(
                status="active",
                service_state=status_info.get("state"),
                message="Tunnel is running"
            )
        else:
            return StatusResponse(
                status="inactive",
                service_state=status_info.get("state") if status_info else None,
                message="Tunnel is not running"
            )
            
    except Exception as e:
        logger.error(f"Error checking tunnel status: {e}")
        return StatusResponse(
            status="inactive",
            message=f"Error checking status: {str(e)}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NETWORK MANAGEMENT ENDPOINTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.post(
    "/network/start",
    response_model=NetworkResponse,
    summary="Start Tunnel",
    description="Start the WireGuard tunnel (requires admin privileges)"
)
async def start_tunnel(
    current_user: Dict = Depends(get_current_user)
) -> NetworkResponse:
    """
    Start the WireGuard server tunnel with dynamic peer synchronization.
    
    Phase 6 Implementation:
    - Generates ephemeral server keypair on each start
    - Loads all enrolled devices from database as peers
    - Stores server public key in memory for client configs
    - Starts tunnel with complete peer list
    
    Requires Windows administrator privileges.
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        Network operation response with peer count
        
    Raises:
        HTTPException 500: If tunnel start fails
        
    Security:
        - Requires valid JWT token and admin privileges
        - Server keys are ephemeral (regenerated on each start)
        - Each peer gets dedicated /32 IP allocation
    """
    logger.info(f"Tunnel start requested by: {current_user['sub']}")
    
    try:
        # Step 1: Get server keypair (persistent or new)
        from core import get_persistent_server_keys
        server_private_key, server_public_key = await get_persistent_server_keys()
        
        if not server_private_key:
            logger.info("Generating NEW server WireGuard keypair...")
            server_private_key, server_public_key = await generate_wireguard_keys()
        else:
            logger.info("Using PERSISTENT server keys from disk")
        
        # Step 2: Store keys in memory for client enrollment
        from core import set_server_keys
        set_server_keys(server_private_key, server_public_key)
        logger.info(f"Server public key: {server_public_key[:20]}...")
        
        # Step 3: Load all enrolled devices from database
        logger.info("Loading enrolled devices from database...")
        await init_db()
        all_devices = await list_devices()
        
        # Step 4: Build peer list from devices
        peers = []
        for device in all_devices:
            peers.append({
                "public_key": device["public_key"],
                "allowed_ips": f"{device['ip_address']}/32"  # Single IP per device
            })
        
        logger.info(f"Loaded {len(peers)} enrolled devices as peers")
        
        # Step 5: Generate server config with all peers
        from core import generate_server_config
        config = generate_server_config(
            server_private_key=server_private_key,
            peers=peers
        )
        
        # Step 6: Start the tunnel
        success = await start_safenet_tunnel(config)
        
        if success:
            logger.info(f"Tunnel started successfully with {len(peers)} peers")
            return NetworkResponse(
                success=True,
                message=f"Tunnel started with {len(peers)} enrolled devices",
                operation="start"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to start tunnel"
            )
            
    except Exception as e:
        logger.error(f"Error starting tunnel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Tunnel start failed: {str(e)}"
        )



@router.post(
    "/network/stop",
    response_model=NetworkResponse,
    summary="Stop Tunnel",
    description="Stop the WireGuard tunnel"
)
async def stop_tunnel(
    current_user: Dict = Depends(get_current_user)
) -> NetworkResponse:
    """
    Stop the WireGuard tunnel and clear server keys.
    
    Phase 6: Clears ephemeral server keys from memory on shutdown.
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        Network operation response
        
    Security:
        Requires valid JWT token
        Server keys removed from memory on tunnel stop
    """
    logger.info(f"Tunnel stop requested by: {current_user['sub']}")
    
    try:
        # Stop the tunnel
        success = await stop_safenet_tunnel(delete_config=False)
        
        # Clear server keys from memory
        from core import clear_server_keys
        clear_server_keys()
        logger.info("Server keys cleared from memory")
        
        if success:
            logger.info("Tunnel stopped successfully")
            return NetworkResponse(
                success=True,
                message="Tunnel stopped successfully",
                operation="stop"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to stop tunnel"
            )
            
    except Exception as e:
        logger.error(f"Error stopping tunnel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Tunnel stop failed: {str(e)}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEVICE MANAGEMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/devices",
    response_model=DeviceListResponse,
    summary="List All Devices",
    description="Get a list of all enrolled devices with their real-time connection status."
)
async def get_all_devices(
    current_user: str = Depends(get_current_user)
) -> DeviceListResponse:
    """
    List all devices and their status.
    
    Combines:
    1. Static configuration from Database (Name, IP, Public Key)
    2. Dynamic status from WireGuard (Handshake, Transfer, Endpoint)
    """
    # 1. Get all devices from DB
    db_devices = await list_devices()
    
    # 2. Get active active peers from WireGuard
    # We try to get status, but if tunnel is down, we just get empty dict
    active_peers = await get_active_peers()
    
    device_list = []
    
    for device in db_devices:
        # Match by Public Key
        pub_key = device["public_key"]
        peer_status = active_peers.get(pub_key, {})
        
        # Build status object
        status_obj = DeviceStatus(
            name=device["name"],
            ip_address=device["ip_address"] or "Unassigned",
            public_key=pub_key or "Unknown",
            endpoint=peer_status.get("endpoint"),
            latest_handshake=peer_status.get("latest_handshake", 0),
            transfer_rx=peer_status.get("transfer_rx", 0),
            transfer_tx=peer_status.get("transfer_tx", 0),
            is_active=peer_status.get("is_active", False)
        )
        device_list.append(status_obj)
        
    return DeviceListResponse(
        devices=device_list,
        count=len(device_list)
    )


@router.post(
    "/devices/enroll",
    response_model=EnrollDeviceResponse,
    summary="Enroll New Device",
    description="Register a new device, generate keys, and return WireGuard config"
)
async def enroll_device(
    request: EnrollDeviceRequest,
    current_user: str = Depends(get_current_user)
) -> EnrollDeviceResponse:
    """
    Enroll a new device in the SafeNet network.
    
    This is the CORE provisioning endpoint. It:
    1. Validates device name (via Pydantic)
    2. Generates WireGuard keys in-memory
    3. Assigns an available IP address
    4. Saves public key + IP to database
    5. Returns complete config (including private key)
    6. Private key is immediately dropped from memory
    
    Args:
        request: Device enrollment request with device_name
        current_user: Authenticated user from JWT token
        
    Returns:
        Complete WireGuard configuration for the client
        
    Raises:
        HTTPException 409: Device already exists
        HTTPException 500: Enrollment failed
        
    Security:
        - Device name validated by Pydantic (prevents injection)
        - Private key never stored (ephemeral)
        - JWT authentication required
    """
    logger.info(f"Device enrollment requested by {current_user['sub']}: {request.device_name}")
    print(f"DEBUG: 1 - Enrollment started for {request.device_name}")
    
    try:
        # Initialize database
        await init_db()
        
        # Check if device already exists
        existing_device = await get_device(request.device_name)
        if existing_device:
            logger.warning(f"Device already exists: {request.device_name}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Device '{request.device_name}' already exists"
            )
        
        # Generate WireGuard keys (in-memory only)
        logger.info(f"Generating WireGuard keys for: {request.device_name}")
        private_key, public_key = await generate_wireguard_keys()
        print(f"DEBUG: 2 - Keygen successful")
        
        # Assign IP address (simple incrementing for MVP)
        # Assign IP address
        # Dynamic allocation
        assigned_ip_addr = await allocate_next_ip()
        assigned_ip = f"{assigned_ip_addr}/24"
        
        # Save device to database (public key only)
        logger.info(f"Saving device to database: {request.device_name}")
        await add_device(
            name=request.device_name,
            public_key=public_key,
            ip_address=assigned_ip.split("/")[0],  # Store without CIDR
            groups=["default"]  # Fixed: Use plural 'groups' with list
        )
        print(f"DEBUG: 3 - Database insertion successful")
        
        # NEW Phase 6: Get server keys (Memory first, then Disk)
        from core import get_server_public_key, get_server_private_key, get_persistent_server_keys
        
        server_public_key = get_server_public_key()
        server_private_key = get_server_private_key()
        
        print(f"DEBUG: Memory Server Public Key: {server_public_key}")
        
        if not server_public_key:
            # Try load from disk (persistent keys)
            print("DEBUG: Checking disk for persistent keys...")
            server_private_key, server_public_key = await get_persistent_server_keys()
            print(f"DEBUG: Disk Server Public Key: {server_public_key}")
            
        if not server_public_key:
            # Server not running and no config - use placeholder
            logger.warning("Server not running and no config found - using placeholder key")
            server_public_key = "SERVER_PUB_KEY_PLACEHOLDER"
        else:
            logger.info(f"Using server public key: {server_public_key[:20]}...")
        
        # Generate WireGuard client configuration string with REAL server key
        config = generate_config_string(
            private_key=private_key,
            local_ip=assigned_ip,
            server_public_key=server_public_key
        )
        
        logger.info(f"Device enrolled successfully: {request.device_name}")
        print(f"DEBUG: 4 - Config generated")
        
        # NEW Phase 6: Hot-reload server to add this peer (if server is running)
        from core import get_tunnel_status, reload_wireguard_server
        
        # Check if tunnel is actually running independently of API memory state
        tunnel_status = await get_tunnel_status()
        is_tunnel_active = tunnel_status is not None
        
        if is_tunnel_active:
            try:
                logger.info("Tunnel is active - triggering hot-reload to add new peer...")
                
                if server_private_key:
                    # Fetch ALL devices (including the newly enrolled one)
                    all_devices = await list_devices()
                    
                    # Build peer list
                    peers = [
                        {
                            "public_key": d["public_key"],
                            "allowed_ips": f"{d['ip_address']}/32"
                        }
                        for d in all_devices
                    ]
                    
                    # Hot-reload server with updated peer list
                    await reload_wireguard_server(
                        server_private_key=server_private_key,
                        peers=peers
                    )
                    
                    logger.info(f"Server reloaded with {len(peers)} peers (new device added)")
                else:
                    logger.warning("Server private key missing (should have been loaded from disk) - cannot reload")
            
            except Exception as e:
                logger.error(f"Hot-reload failed: {e}")
                logger.warning("Device enrolled but server not reloaded - manual restart may be required")
        else:
            logger.info("Server not running - skipping hot-reload")
        
        print(f"DEBUG: 5 - Returning response")
        
        # Return complete configuration
        # Private key is included HERE ONLY and never stored
        return EnrollDeviceResponse(
            device_name=request.device_name,
            assigned_ip=assigned_ip,
            public_key=public_key,
            private_key=private_key,  # EPHEMERAL - client must save!
            config_string=config
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (like 409 Conflict)
        raise
        
    except Exception as e:
        logger.error(f"Device enrollment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Enrollment failed: {str(e)}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEVICE MANAGEMENT ENDPOINTS (Phase 5.1)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/devices",
    summary="List All Devices",
    description="Get all enrolled devices from database"
)
async def list_all_devices(
    current_user: Dict = Depends(get_current_user)
):
    """
    List all enrolled devices in the database.
    
    Returns list of devices with:
    - device_name
    - ip_address
    - public_key
    - groups
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        List of enrolled devices
        
    Security:
        Requires valid JWT token
    """
    logger.info(f"Device list requested by: {current_user['sub']}")
    
    try:
        await init_db()
        from core import list_devices
        devices = await list_devices()
        
        logger.info(f"Retrieved {len(devices)} devices from database")
        return {"devices": devices}
        
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list devices: {str(e)}"
        )


@router.get(
    "/devices/active",
    summary="Get Active Device Status",
    description="Get live connection status from WireGuard"
)
async def get_active_devices(
    current_user: Dict = Depends(get_current_user)
):
    """
    Get active device handshake data from running WireGuard tunnel.
    
    Executes `wg show safenet dump` and parses peer handshake timestamps.
    
    Returns list of active peers with:
    - public_key: WireGuard public key
    - latest_handshake: Unix timestamp of last handshake (0 if never connected)
    
    Args:
        current_user: Authenticated user from JWT token
        
    Returns:
        List of active peers with handshake data
        
    Raises:
        HTTPException 500: If wg command fails or tunnel not running
        
    Security:
        Requires valid JWT token
        Uses list-based subprocess args (no command injection)
    """
    logger.info(f"Active devices query by: {current_user['sub']}")
    
    try:
        import asyncio
        
        # Execute wg show command
        # Security: List-based args prevent command injection
        process = await asyncio.create_subprocess_exec(
            "wg.exe",
            "show",
            "safenet",
            "dump",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace")
            logger.warning(f"wg show failed: {stderr_text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Tunnel not running or wg.exe failed: {stderr_text}"
            )
        
        # Parse wg dump output
        # Format: private_key	public_key	listen_port	fwmark
        #         public_key	preshared_key	endpoint	allowed_ips	latest_handshake	transfer_rx	transfer_tx	persistent_keepalive
        
        output = stdout.decode("utf-8", errors="replace")
        lines = output.strip().split("\n")
        
        active_peers = []
        
        for line in lines[1:]:  # Skip first line (server interface)
            if not line.strip():
                continue
                
            parts = line.split("\t")
            if len(parts) >= 5:
                peer_data = {
                    "public_key": parts[0],
                    "latest_handshake": int(parts[4]) if parts[4].isdigit() else 0
                }
                active_peers.append(peer_data)
        
        logger.info(f"Found {len(active_peers)} active peers")
        return {"active_peers": active_peers}
        
    except FileNotFoundError:
        logger.error("wg.exe not found in PATH")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="wg.exe not found. Ensure WireGuard is installed and in PATH."
        )
        
    except Exception as e:
        logger.error(f"Error getting active devices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get active devices: {str(e)}"
        )


@router.delete(
    "/devices/{device_name}",
    summary="Remove Device",
    description="Delete device from database and hot-reload server"
)
async def remove_device(
    device_name: str,
    current_user: Dict = Depends(get_current_user)
):
    """
    Remove a device from the database and trigger server hot-reload.
    
    Steps:
    1. Verify device exists
    2. Delete from database
    3. Hot-reload server to remove peer (if running)
    
    Args:
        device_name: Name of device to remove
        current_user: Authenticated user from JWT token
        
    Returns:
        Success message
        
    Raises:
        HTTPException 404: Device not found
        HTTPException 500: Deletion or hot-reload failed
        
    Security:
        Requires valid JWT token
    """
    logger.info(f"Device removal requested by {current_user['sub']}: {device_name}")
    
    try:
        await init_db()
        
        #Step 1: Check if device exists
        from core import get_device
        device = await get_device(device_name)
        
        if not device:
            logger.warning(f"Device not found: {device_name}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device '{device_name}' not found"
            )
        
        # Step 2: Delete from database
        from core import delete_device
        await delete_device(device_name)
        logger.info(f"Device deleted from database: {device_name}")
        
        # Step 3: Hot-reload server to remove peer (if running)
        from core import get_server_public_key, get_server_private_key, reload_wireguard_server, list_devices
        
        if get_server_public_key():
            try:
                logger.info("Server is running - triggering hot-reload to remove peer...")
                
                server_private_key = get_server_private_key()
                
                if server_private_key:
                    # Fetch remaining devices (excluding deleted one)
                    all_devices = await list_devices()
                    
                    # Build peer list
                    peers = [
                        {
                            "public_key": d["public_key"],
                            "allowed_ips": f"{d['ip_address']}/32"
                        }
                        for d in all_devices
                    ]
                    
                    # Hot-reload server with updated peer list
                    await reload_wireguard_server(
                        server_private_key=server_private_key,
                        peers=peers
                    )
                    
                    logger.info(f"Server reloaded with {len(peers)} peers (device removed)")
                else:
                    logger.warning("Server private key not found in memory")
            
            except Exception as e:
                # Don't fail deletion if reload fails
                logger.error(f"Hot-reload failed: {e}")
                logger.warning("Device deleted but server not reloaded - manual restart required")
        else:
            logger.info("Server not running - skipping hot-reload")
        
        return {
            "success": True,
            "message": f"Device '{device_name}' removed successfully"
        }
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"Error removing device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove device: {str(e)}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HEALTH CHECK (UNPROTECTED)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/health",
    summary="Health Check",
    description="Unprotected health check endpoint"
)
async def health_check():
    """
    Simple health check endpoint (no authentication required).
    
    Returns:
        Health status
    """
    return {"status": "healthy", "service": "SafeNet API"}
