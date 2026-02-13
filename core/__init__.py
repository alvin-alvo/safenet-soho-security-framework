"""
SafeNet Core Module

This module provides the foundational cryptographic and network management
components for the SafeNet Zero-Trust micro-perimeter framework.

Components:
- keygen: Secure, in-memory WireGuard key generation
- schemas: Pydantic validation models for policy configuration
- db: Async SQLite database for network state management
- policy: YAML policy parser with strict validation

Security Architecture: "Antigravity"
- Zero-disk-key cryptography
- Fully asynchronous subprocess execution
- Strict input sanitization
- TLS/HTTPS enforced communications
"""

__version__ = "0.2.0"
__author__ = "SafeNet Development Team"

# Import key generation function for module-level access
from .keygen import generate_wireguard_keys

# Import database functions
from .db import (
    init_db,
    add_device,
    get_device,
    list_devices,
    delete_device,
    get_devices_in_group
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

__all__ = [
    # Keygen
    "generate_wireguard_keys",
    
    # Database
    "init_db",
    "add_device",
    "get_device",
    "list_devices",
    "delete_device",
    "get_devices_in_group",
    
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
]
