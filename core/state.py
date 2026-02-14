"""
SafeNet Core - Server State Management

This module manages the ephemeral server state, including:
- Server WireGuard keypair (generated on tunnel start)
- Tunnel running status
- Server configuration metadata

Security Note:
- Server keys are stored in-memory only (ephemeral)
- Keys are regenerated on each tunnel start
- Phase 7 will add database persistence for production use

Author: SafeNet Security Team
License: GPL-3.0
"""

import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# IN-MEMORY SERVER STATE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Global state for server keys and status (MVP - move to DB in Phase 7)
_server_state: Dict[str, Optional[str]] = {
    "private_key": None,
    "public_key": None,
    "is_running": False,
    "tunnel_name": "safenet",
    "listen_port": 65065
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STATE MANAGEMENT FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def set_server_keys(private_key: str, public_key: str) -> None:
    """
    Store server keypair in memory.
    
    This function is called when the WireGuard tunnel starts.
    The keys are ephemeral and will be lost when the process exits.
    
    Args:
        private_key: Server's WireGuard private key (Base64, 44 chars)
        public_key: Server's WireGuard public key (Base64, 44 chars)
        
    Security:
        - Keys stored in process memory only
        - Not persisted to disk or database (MVP)
        - Regenerated on each tunnel start
    """
    global _server_state
    
    _server_state["private_key"] = private_key
    _server_state["public_key"] = public_key
    _server_state["is_running"] = True
    
    logger.info(f"Server keys stored in memory. Public key: {public_key[:20]}...")


def get_server_public_key() -> Optional[str]:
    """
    Retrieve server public key for client configurations.
    
    This function is called during device enrollment to embed the
    server's public key in the client's WireGuard config.
    
    Returns:
        Server's public key if tunnel is running, None otherwise
        
    Usage:
        server_pub_key = get_server_public_key()
        if server_pub_key:
            # Use real key
            config = generate_config_string(..., server_public_key=server_pub_key)
        else:
            # Use placeholder (server not running)
            config = generate_config_string(...)
    """
    public_key = _server_state.get("public_key")
    
    if public_key:
        logger.debug(f"Returning server public key: {public_key[:20]}...")
    else:
        logger.warning("Server public key requested but tunnel not running")
    
    return public_key


def get_server_private_key() -> Optional[str]:
    """
    Retrieve server private key for hot-reload operations.
    
    This is used internally when regenerating the server config
    after a new device enrolls.
    
    Returns:
        Server's private key if tunnel is running, None otherwise
        
    Security:
        - Private key never exposed to API clients
        - Only used for internal config generation
    """
    return _server_state.get("private_key")


def is_server_running() -> bool:
    """
    Check if the WireGuard tunnel is currently running.
    
    Returns:
        True if tunnel is active, False otherwise
    """
    return _server_state.get("is_running", False)


def clear_server_keys() -> None:
    """
    Clear server keys from memory.
    
    This function is called when the WireGuard tunnel stops.
    It ensures keys are removed from memory for security.
    
    Security:
        - Prevents key leakage after tunnel shutdown
        - Forces key regeneration on next start
    """
    global _server_state
    
    logger.info("Clearing server keys from memory")
    
    _server_state["private_key"] = None
    _server_state["public_key"] = None
    _server_state["is_running"] = False


def get_server_state() -> Dict[str, Optional[str]]:
    """
    Get complete server state for debugging/monitoring.
    
    Returns:
        Dictionary with server state (keys redacted for security)
        
    Note:
        Private key is not included in response for security
    """
    return {
        "is_running": _server_state["is_running"],
        "public_key": _server_state["public_key"],
        "tunnel_name": _server_state["tunnel_name"],
        "listen_port": _server_state["listen_port"],
        "has_private_key": _server_state["private_key"] is not None
    }
