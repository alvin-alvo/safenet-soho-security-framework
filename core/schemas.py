"""
SafeNet Core - Pydantic Validation Schemas

This module defines strict input validation models for the SafeNet policy engine.
All external data (YAML policies, API inputs) MUST pass through these schemas
to prevent command injection, SQL injection, and malformed configuration attacks.

Security Principles:
- Strict regex validation on device names (alphanumeric + underscore/hyphen only)
- Enum-based validation for action types (allow/deny)
- IP address format validation
- Group name sanitization

Author: SafeNet Development Team
License: Internal Use Only
"""

import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress
from enum import Enum


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECURITY CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Strict regex patterns for input validation
# These prevent OS command injection when names are passed to subprocess calls
DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
GROUP_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{2,32}$")

# WireGuard key validation (Base64, 44 characters)
WIREGUARD_KEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENUMS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AccessAction(str, Enum):
    """
    Defines valid access control actions.
    
    Using an Enum prevents injection of arbitrary action types and ensures
    only "allow" or "deny" can be specified in policies.
    """
    ALLOW = "allow"
    DENY = "deny"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PYDANTIC MODELS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DeviceNode(BaseModel):
    """
    Represents a device/peer in the SafeNet network.
    
    This model validates device configurations from policy.yml and API requests.
    The strict validation prevents command injection attacks when device names
    are later passed to Windows subprocess calls (wg.exe, wireguard.exe).
    
    Attributes:
        name: Device identifier (alphanumeric + underscore/hyphen, 3-32 chars)
        groups: List of group memberships for access control rules
        public_key: Optional WireGuard public key (Base64, 44 chars)
        ip_address: Optional assigned IP address in the mesh network
    
    Security Notes:
        - Device names are validated against DEVICE_NAME_PATTERN
        - Special characters like `;`, `&`, `|`, `$()` are REJECTED
        - This prevents injection attacks: `device; rm -rf /` becomes invalid
    
    Example:
        >>> device = DeviceNode(name="laptop01", groups=["work", "trusted"])
        >>> device = DeviceNode(name="vm; rm -rf /", groups=["malicious"])
        ValidationError: Device name contains invalid characters
    """
    
    name: str = Field(
        ...,
        min_length=3,
        max_length=32,
        description="Unique device identifier (alphanumeric, underscore, hyphen only)"
    )
    
    groups: List[str] = Field(
        default_factory=list,
        description="List of group names this device belongs to"
    )
    
    public_key: Optional[str] = Field(
        default=None,
        description="WireGuard public key (Base64, 44 characters)"
    )
    
    ip_address: Optional[str] = Field(
        default=None,
        description="Assigned IP address (e.g., 10.0.0.5/24)"
    )
    
    @field_validator("name")
    @classmethod
    def validate_device_name(cls, value: str) -> str:
        """
        Validates device name against strict regex pattern.
        
        Security: Rejects any name containing shell metacharacters or
        special characters that could enable command injection attacks.
        
        Args:
            value: The device name to validate
            
        Returns:
            The validated device name (lowercase for consistency)
            
        Raises:
            ValueError: If name contains invalid characters or is malformed
        """
        if not DEVICE_NAME_PATTERN.match(value):
            raise ValueError(
                f"Device name '{value}' is invalid. "
                f"Must be 3-32 characters, alphanumeric with underscores or hyphens only. "
                f"No special characters allowed (prevents command injection)."
            )
        
        # Convert to lowercase for case-insensitive uniqueness
        return value.lower()
    
    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: List[str]) -> List[str]:
        """
        Validates group names against strict regex pattern.
        
        Each group name must be alphanumeric with underscores/hyphens only.
        This prevents injection attacks through group names.
        
        Args:
            value: List of group names
            
        Returns:
            List of validated group names (lowercase)
            
        Raises:
            ValueError: If any group name is invalid
        """
        validated_groups = []
        for group in value:
            if not GROUP_NAME_PATTERN.match(group):
                raise ValueError(
                    f"Group name '{group}' is invalid. "
                    f"Must be 2-32 characters, alphanumeric with underscores or hyphens only."
                )
            validated_groups.append(group.lower())
        
        return validated_groups
    
    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: Optional[str]) -> Optional[str]:
        """
        Validates WireGuard public key format.
        
        WireGuard keys are Base64-encoded, exactly 44 characters including
        the trailing '=' padding.
        
        Args:
            value: The public key to validate
            
        Returns:
            The validated public key
            
        Raises:
            ValueError: If key format is invalid
        """
        if value is None:
            return value
        
        if not WIREGUARD_KEY_PATTERN.match(value):
            raise ValueError(
                f"Invalid WireGuard public key format. "
                f"Must be Base64-encoded, exactly 44 characters (including '=' padding)."
            )
        
        return value
    
    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: Optional[str]) -> Optional[str]:
        """
        Validates IP address format.
        
        Accepts both IPv4 and IPv6 addresses with optional CIDR notation.
        
        Args:
            value: The IP address to validate
            
        Returns:
            The validated IP address
            
        Raises:
            ValueError: If IP format is invalid
        """
        if value is None:
            return value
        
        # Basic IP validation (more robust validation in database layer)
        # This prevents obvious injection attempts like "127.0.0.1; rm -rf /"
        import ipaddress
        try:
            # Strip CIDR notation if present
            ip_only = value.split('/')[0]
            ipaddress.ip_address(ip_only)
            return value
        except ValueError:
            raise ValueError(
                f"Invalid IP address format: '{value}'. "
                f"Must be a valid IPv4 or IPv6 address."
            )


class AccessRule(BaseModel):
    """
    Represents a network access control rule.
    
    Defines which groups can communicate with other groups. The SafeNet
    framework enforces a "Default Deny" posture, so only explicitly allowed
    traffic is permitted.
    
    Attributes:
        from_group: Source group name
        to_group: Destination group name
        action: Access decision (allow or deny)
    
    Example:
        >>> rule = AccessRule(from_group="work", to_group="trusted", action="allow")
        >>> rule = AccessRule(from_group="iot", to_group="work", action="deny")
    """
    
    from_group: str = Field(
        ...,
        alias="from",
        description="Source group name"
    )
    
    to_group: str = Field(
        ...,
        alias="to",
        description="Destination group name"
    )
    
    action: AccessAction = Field(
        ...,
        description="Access control action (allow or deny)"
    )
    
    @field_validator("from_group", "to_group")
    @classmethod
    def validate_group_name(cls, value: str) -> str:
        """
        Validates group names in access rules.
        
        Args:
            value: The group name to validate
            
        Returns:
            The validated group name (lowercase)
            
        Raises:
            ValueError: If group name is invalid
        """
        if not GROUP_NAME_PATTERN.match(value):
            raise ValueError(
                f"Group name '{value}' is invalid. "
                f"Must be 2-32 characters, alphanumeric with underscores or hyphens only."
            )
        
        return value.lower()
    
    class Config:
        """Pydantic configuration to allow 'from' and 'to' as field aliases."""
        populate_by_name = True


class SafeNetPolicy(BaseModel):
    """
    Root policy model representing the complete network configuration.
    
    This is the top-level schema for data/policy.yml. All policy files
    must validate against this schema before being applied to the network.
    
    Attributes:
        devices: List of device configurations
        access_rules: List of access control rules (optional)
    
    Security Notes:
        - All device names are validated for injection attacks
        - All group names are sanitized
        - Access rules enforce enum-based actions (allow/deny only)
    
    Example YAML:
        ```yaml
        devices:
          - name: laptop01
            groups: [work, trusted]
          - name: phone01
            groups: [mobile, untrusted]
        
        access_rules:
          - from: work
            to: trusted
            action: allow
          - from: untrusted
            to: work
            action: deny
        ```
    """
    
    devices: List[DeviceNode] = Field(
        ...,
        min_length=1,
        description="List of devices/peers in the network (minimum 1 required)"
    )
    
    access_rules: List[AccessRule] = Field(
        default_factory=list,
        description="List of access control rules (optional, default deny all)"
    )
    
    @field_validator("devices")
    @classmethod
    def validate_unique_device_names(cls, devices: List[DeviceNode]) -> List[DeviceNode]:
        """
        Ensures all device names are unique.
        
        Duplicate device names would cause conflicts in IP assignment and
        WireGuard configuration generation.
        
        Args:
            devices: List of device configurations
            
        Returns:
            The validated list of devices
            
        Raises:
            ValueError: If duplicate device names are found
        """
        names = [device.name for device in devices]
        if len(names) != len(set(names)):
            duplicates = [name for name in names if names.count(name) > 1]
            raise ValueError(
                f"Duplicate device names found: {set(duplicates)}. "
                f"All device names must be unique."
            )
        
        return devices
    
    @field_validator("access_rules")
    @classmethod
    def validate_access_rules(cls, rules: List[AccessRule]) -> List[AccessRule]:
        """
        Validates access rules for logical consistency.
        
        Currently performs basic validation. Future enhancements:
        - Detect conflicting rules (same from/to with different actions)
        - Warn about unreachable groups (groups with no allow rules)
        - Optimize rule ordering for performance
        
        Args:
            rules: List of access control rules
            
        Returns:
            The validated list of rules
        """
        # Currently just returns rules as-is
        # Future: Add conflict detection, optimization, etc.
        return rules


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VALIDATION HELPER FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_valid_device_name(name: str) -> bool:
    """
    Quick validation check for device names.
    
    Args:
        name: Device name to validate
        
    Returns:
        True if valid, False otherwise
    """
    return bool(DEVICE_NAME_PATTERN.match(name))


def is_valid_wireguard_key(key: str) -> bool:
    """
    Quick validation check for WireGuard keys.
    
    Args:
        key: WireGuard key to validate
        
    Returns:
        True if valid, False otherwise
    """
    return bool(WIREGUARD_KEY_PATTERN.match(key))
