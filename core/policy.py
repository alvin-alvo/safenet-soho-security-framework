"""
SafeNet Core - YAML Policy Parser

This module safely loads and validates the SafeNet policy configuration file.
Uses yaml.safe_load to prevent code injection and Pydantic for strict validation.

Security Principles:
- NEVER use yaml.load (allows arbitrary code execution)
- ALWAYS use yaml.safe_load (restricts to safe YAML types)
- Validate all data through Pydantic schemas
- Fail-secure on parse errors

Author: SafeNet Development Team
License: Internal Use Only
"""

import yaml
from pathlib import Path
from typing import Optional
import logging

# Import our Pydantic validation schemas
from .schemas import SafeNetPolicy, DeviceNode, AccessRule

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POLICY FILE CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DEFAULT_POLICY_PATH = Path("data/policy.yml")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POLICY LOADING FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def load_policy(policy_path: Path = DEFAULT_POLICY_PATH) -> SafeNetPolicy:
    """
    Load and validate the SafeNet policy configuration file.
    
    This is the primary function for reading policy.yml. It performs:
    1. Safe YAML loading (prevents code injection)
    2. Schema validation via Pydantic (prevents malformed configs)
    3. Security constraint enforcement (regex validation on names)
    
    CRITICAL SECURITY: Uses yaml.safe_load, NOT yaml.load
    
    Why yaml.safe_load?
    - yaml.load() can execute arbitrary Python code embedded in YAML
    - Example attack: `!!python/object/apply:os.system ["rm -rf /"]`
    - yaml.safe_load() ONLY constructs simple Python objects (str, int, list, dict)
    
    Args:
        policy_path: Path to the policy.yml file
        
    Returns:
        Validated SafeNetPolicy object
        
    Raises:
        FileNotFoundError: If policy.yml doesn't exist
        yaml.YAMLError: If YAML syntax is invalid
        pydantic.ValidationError: If policy violates schema constraints
        
    Example:
        >>> policy = load_policy()
        >>> for device in policy.devices:
        ...     print(f"{device.name}: {device.groups}")
        >>> 
        >>> for rule in policy.access_rules:
        ...     print(f"{rule.from_group} -> {rule.to_group}: {rule.action}")
    """
    logger.info(f"Loading SafeNet policy from: {policy_path}")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 1: Verify file exists
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if not policy_path.exists():
        logger.error(f"Policy file not found: {policy_path}")
        raise FileNotFoundError(
            f"SafeNet policy file not found: {policy_path}\n"
            f"Please create a policy.yml file with your network configuration."
        )
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 2: Read and parse YAML (SAFELY)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    try:
        with open(policy_path, 'r', encoding='utf-8') as f:
            # SECURITY: Use safe_load, NEVER yaml.load
            # This prevents code injection attacks via malicious YAML
            raw_policy = yaml.safe_load(f)
            
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML syntax in policy file: {e}")
        raise ValueError(
            f"Policy file contains invalid YAML syntax: {e}\n"
            f"Please check your policy.yml file for syntax errors."
        )
    
    except Exception as e:
        logger.error(f"Failed to read policy file: {e}")
        raise RuntimeError(f"Error reading policy file: {e}")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 3: Validate against Pydantic schema
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    try:
        # Pass the raw dictionary through Pydantic validation
        # This enforces:
        # - Required fields are present
        # - Device names match DEVICE_NAME_PATTERN regex
        # - Group names match GROUP_NAME_PATTERN regex
        # - Access actions are "allow" or "deny" only
        # - No duplicate device names
        policy = SafeNetPolicy(**raw_policy)
        
        logger.info(
            f"Policy loaded successfully: "
            f"{len(policy.devices)} devices, "
            f"{len(policy.access_rules)} access rules"
        )
        
        return policy
        
    except Exception as e:
        # Pydantic ValidationError will have detailed error messages
        logger.error(f"Policy validation failed: {e}")
        raise ValueError(
            f"Policy file validation failed: {e}\n\n"
            f"Common issues:\n"
            f"- Device names must be alphanumeric with underscores/hyphens (3-32 chars)\n"
            f"- Group names must be alphanumeric with underscores/hyphens (2-32 chars)\n"
            f"- Access actions must be 'allow' or 'deny'\n"
            f"- Device names must be unique\n"
        )


def validate_policy_file(policy_path: Path = DEFAULT_POLICY_PATH) -> bool:
    """
    Validate a policy file without loading it into memory.
    
    Useful for pre-flight checks before applying a new policy.
    
    Args:
        policy_path: Path to the policy.yml file
        
    Returns:
        True if valid, False if invalid
        
    Example:
        >>> if validate_policy_file(Path("new_policy.yml")):
        ...     print("Policy is valid, safe to apply")
        ... else:
        ...     print("Policy has errors, cannot apply")
    """
    try:
        load_policy(policy_path)
        return True
    except Exception as e:
        logger.warning(f"Policy validation failed: {e}")
        return False


def create_default_policy(policy_path: Path = DEFAULT_POLICY_PATH) -> None:
    """
    Create a default policy.yml template file.
    
    Generates a starter configuration with example devices and rules.
    Useful for first-time setup.
    
    Args:
        policy_path: Path where to create the policy file
        
    Raises:
        FileExistsError: If policy file already exists (safety check)
        
    Example:
        >>> create_default_policy()
        >>> # Creates data/policy.yml with example configuration
    """
    if policy_path.exists():
        raise FileExistsError(
            f"Policy file already exists: {policy_path}\n"
            f"To avoid overwriting your existing policy, this function will not proceed.\n"
            f"If you want to reset your policy, manually delete the file first."
        )
    
    # Ensure the data directory exists
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Default policy template
    default_policy_yaml = """# SafeNet Policy Configuration
# This file defines your Zero-Trust network topology
# 
# Security Notes:
# - Device names: alphanumeric, underscore, hyphen only (prevents command injection)
# - Default posture: DENY ALL (only explicitly allowed traffic is permitted)
# - Groups: logical groupings for access control rules

# Define network devices/peers
devices:
  # Work devices - trusted endpoints
  - name: worklaptop
    groups: [work, trusted]
  
  - name: workdesktop
    groups: [work, trusted]
  
  # Mobile devices - partially trusted
  - name: phone01
    groups: [mobile, trusted]
  
  # IoT devices - untrusted by default
  - name: smarttv
    groups: [iot, untrusted]
  
  - name: smart_speaker
    groups: [iot, untrusted]

# Define access control rules
access_rules:
  # Allow work devices to communicate with other trusted devices
  - from: work
    to: trusted
    action: allow
  
  # Allow mobile devices to reach work resources
  - from: mobile
    to: work
    action: allow
  
  # DENY IoT devices from reaching work resources (explicit deny)
  - from: iot
    to: work
    action: deny
  
  # DENY IoT devices from reaching mobile devices
  - from: iot
    to: mobile
    action: deny

# Default behavior: If no rule matches, traffic is DENIED (Zero-Trust principle)
"""
    
    # Write the template to file
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(default_policy_yaml)
    
    logger.info(f"Created default policy file: {policy_path}")
    print(f"[SUCCESS] Default policy created at: {policy_path}")
    print("Please review and customize the policy for your network.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POLICY ANALYSIS UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_policy_summary(policy: SafeNetPolicy) -> dict:
    """
    Generate a summary of a policy for display/logging.
    
    Args:
        policy: Validated SafeNetPolicy object
        
    Returns:
        Dictionary with policy statistics
        
    Example:
        >>> policy = load_policy()
        >>> summary = get_policy_summary(policy)
        >>> print(f"Devices: {summary['device_count']}")
        >>> print(f"Groups: {summary['unique_groups']}")
    """
    # Collect all unique group names
    all_groups = set()
    for device in policy.devices:
        all_groups.update(device.groups)
    
    # Count allow vs deny rules
    allow_rules = sum(1 for rule in policy.access_rules if rule.action.value == "allow")
    deny_rules = sum(1 for rule in policy.access_rules if rule.action.value == "deny")
    
    return {
        "device_count": len(policy.devices),
        "device_names": [d.name for d in policy.devices],
        "unique_groups": sorted(all_groups),
        "group_count": len(all_groups),
        "total_rules": len(policy.access_rules),
        "allow_rules": allow_rules,
        "deny_rules": deny_rules,
    }


def print_policy_summary(policy: SafeNetPolicy) -> None:
    """
    Print a human-readable policy summary to console.
    
    Args:
        policy: Validated SafeNetPolicy object
        
    Example:
        >>> policy = load_policy()
        >>> print_policy_summary(policy)
    """
    summary = get_policy_summary(policy)
    
    print("=" * 60)
    print("SafeNet Policy Summary")
    print("=" * 60)
    print(f"Total Devices: {summary['device_count']}")
    print(f"Unique Groups: {summary['group_count']}")
    print(f"Access Rules: {summary['total_rules']} "
          f"({summary['allow_rules']} allow, {summary['deny_rules']} deny)")
    print()
    print("Devices:")
    for device in policy.devices:
        print(f"  - {device.name}: {', '.join(device.groups)}")
    print()
    print("Access Rules:")
    for rule in policy.access_rules:
        print(f"  - {rule.from_group} -> {rule.to_group}: {rule.action.value.upper()}")
    print("=" * 60)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST/VALIDATION BLOCK
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    """
    Test/demonstration block for the policy parser.
    
    Run this file directly to:
    1. Create a default policy.yml template
    2. Load and validate the policy
    3. Display a summary
    """
    import sys
    from pathlib import Path
    
    print("SafeNet Policy Parser - Test Mode")
    print()
    
    # Check if policy file exists
    if not DEFAULT_POLICY_PATH.exists():
        print(f"[INFO] Policy file not found: {DEFAULT_POLICY_PATH}")
        print("[INFO] Creating default policy template...")
        try:
            create_default_policy()
        except Exception as e:
            print(f"[ERROR] Failed to create default policy: {e}")
            sys.exit(1)
    
    # Load and validate policy
    print(f"[INFO] Loading policy from: {DEFAULT_POLICY_PATH}")
    try:
        policy = load_policy()
        print("[SUCCESS] Policy loaded and validated successfully")
        print()
        
        # Display summary
        print_policy_summary(policy)
        
    except Exception as e:
        print(f"[ERROR] Policy validation failed: {e}")
        sys.exit(1)
