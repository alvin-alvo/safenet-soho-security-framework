"""
SafeNet Core Module

This module provides the foundational cryptographic and network management
components for the SafeNet Zero-Trust micro-perimeter framework.

Components:
- keygen: Secure, in-memory WireGuard key generation
- schemas: Pydantic validation models for policy configuration
- db: Async SQLite database for network state management
- policy: YAML policy parser with strict validation
- engine: Async WireGuard tunnel management (Windows)

Security Architecture: "Antigravity"
- Zero-disk-key cryptography
- Fully asynchronous subprocess execution
- Strict input sanitization
- TLS/HTTPS enforced communications
"""

__version__ = "0.4.0"
__author__ = "SafeNet Development Team"

# Import key generation function for module-level access
from .keygen import (
    generate_wireguard_keys,
    derive_public_key
)

# Import database functions
from .db import (
    init_db,
    add_device,
    get_device,
    list_devices,
    delete_device,
    get_devices_in_group,
    allocate_next_ip
)

# Import policy parser
from .policy import (
    load_policy,
    validate_policy_file,
    create_default_policy,
    get_policy_summary,
    print_policy_summary
)

# Import Pydantic schemas
from .schemas import (
    DeviceNode,
    AccessRule,
    SafeNetPolicy,
    AccessAction,
    is_valid_device_name,
    is_valid_wireguard_key
)

# Import WireGuard engine (Phase 3)
from .engine import (
    generate_config_string,
    generate_server_config,
    start_safenet_tunnel,
    stop_safenet_tunnel,
    reload_wireguard_server,
    get_tunnel_status,
    get_active_peers,
    get_persistent_server_keys
)

# Import server state management (Phase 6)
from .state import (
    set_server_keys,
    get_server_public_key,
    get_server_private_key,
    is_server_running,
    clear_server_keys,
    get_server_state
)

__all__ = [
    # Keygen
    "generate_wireguard_keys",
    "derive_public_key",
    
    # Database
    "init_db",
    "add_device",
    "get_device",
    "list_devices",
    "delete_device",
    "get_devices_in_group",
    "allocate_next_ip",
    
    # Policy
    "load_policy",
    "validate_policy_file",
    "create_default_policy",
    "get_policy_summary",
    "print_policy_summary",
    
    # Schemas
    "DeviceNode",
    "AccessRule",
    "SafeNetPolicy",
    "AccessAction",
    "is_valid_device_name",
    "is_valid_wireguard_key",
    
    # Engine (Phase 3)
    "generate_config_string",
    "generate_server_config",
    "start_safenet_tunnel",
    "stop_safenet_tunnel",
    "reload_wireguard_server",
    "get_tunnel_status",
    "get_active_peers",
    "get_persistent_server_keys",
    
    # State Management (Phase 6)
    "set_server_keys",
    "get_server_public_key",
    "get_server_private_key",
    "is_server_running",
    "clear_server_keys",
    "get_server_state",
]
