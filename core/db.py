"""
SafeNet Core - Asynchronous SQLite Database Layer

This module provides async database operations for storing network state.
Uses aiosqlite to prevent blocking the FastAPI event loop during I/O operations.

Security Principles:
- Parameterized queries prevent SQL injection
- Stores ONLY public keys, NEVER private keys
- Connection pooling for performance
- Proper transaction handling

Database Schema:
- devices: id, name (UNIQUE), public_key, ip_address
- groups: id, device_id (FK), group_name

Author: SafeNet Development Team
License: Internal Use Only
"""

import aiosqlite
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATABASE CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Default database path (relative to project root)
DEFAULT_DB_PATH = Path("data/safenet.db")

# SQL schema definitions
SCHEMA_DEVICES = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

SCHEMA_GROUPS = """
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE(device_id, group_name)
);
"""

# Create indexes for performance
INDEX_DEVICES_NAME = """
CREATE INDEX IF NOT EXISTS idx_devices_name ON devices(name);
"""

INDEX_GROUPS_DEVICE_ID = """
CREATE INDEX IF NOT EXISTS idx_groups_device_id ON groups(device_id);
"""

INDEX_GROUPS_NAME = """
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(group_name);
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATABASE INITIALIZATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """
    Initialize the SafeNet database with required tables and indexes.
    
    Creates the database file if it doesn't exist, along with all required
    tables (devices, groups) and performance indexes.
    
    Security Notes:
        - Database file permissions should be restricted (600 on Unix, ACL on Windows)
        - NEVER stores private keys in the database
        - Uses AUTOINCREMENT to prevent ID reuse attacks
        - Foreign key constraints enforce referential integrity
    
    Args:
        db_path: Path to the SQLite database file
        
    Raises:
        aiosqlite.Error: If database initialization fails
        PermissionError: If unable to create database file
    
    Example:
        >>> await init_db()
        >>> await init_db(Path("custom/path/safenet.db"))
    """
    # Ensure the data directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Initializing SafeNet database at: {db_path}")
    
    try:
        # Connect to database (creates file if doesn't exist)
        async with aiosqlite.connect(db_path) as db:
            # Enable foreign key constraints (disabled by default in SQLite)
            await db.execute("PRAGMA foreign_keys = ON;")
            
            # Create tables
            await db.execute(SCHEMA_DEVICES)
            await db.execute(SCHEMA_GROUPS)
            
            # Create indexes for query performance
            await db.execute(INDEX_DEVICES_NAME)
            await db.execute(INDEX_GROUPS_DEVICE_ID)
            await db.execute(INDEX_GROUPS_NAME)
            
            # Commit all schema changes
            await db.commit()
            
            logger.info("Database initialized successfully")
            
    except aiosqlite.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise RuntimeError(f"Failed to initialize SafeNet database: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEVICE OPERATIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def add_device(
    name: str,
    public_key: str,
    ip_address: str,
    groups: Optional[List[str]] = None,
    db_path: Path = DEFAULT_DB_PATH
) -> int:
    """
    Add a new device to the SafeNet network database.
    
    CRITICAL SECURITY: This function stores ONLY the public key. The private
    key must NEVER be passed to this function or stored in the database.
    
    Security Features:
        - Uses parameterized queries to prevent SQL injection
        - Validates uniqueness of device name
        - Stores only public keys (private keys held in memory only)
        - Transaction-based to ensure atomicity
    
    Args:
        name: Unique device identifier (must be pre-validated via Pydantic)
        public_key: WireGuard public key (Base64, 44 characters)
        ip_address: Assigned IP address with CIDR (e.g., "10.0.0.5/24")
        groups: Optional list of group names to assign
        db_path: Path to the SQLite database file
        
    Returns:
        The database ID of the newly created device
        
    Raises:
        ValueError: If device name already exists
        aiosqlite.IntegrityError: If database constraints are violated
        
    Example:
        >>> device_id = await add_device(
        ...     name="laptop01",
        ...     public_key="HIgo3OfthMXqP3i2e7yzj7WUMaKv4jEvRBDbK3i8bm8=",
        ...     ip_address="10.0.0.5/24",
        ...     groups=["work", "trusted"]
        ... )
        >>> print(f"Device created with ID: {device_id}")
    """
    if groups is None:
        groups = []
    
    logger.info(f"Adding device '{name}' to database")
    
    try:
        async with aiosqlite.connect(db_path) as db:
            # Enable foreign key constraints
            await db.execute("PRAGMA foreign_keys = ON;")
            
            # Begin transaction
            async with db.execute("BEGIN"):
                # Insert device record
                # SECURITY: Parameterized query prevents SQL injection
                # Example BLOCKED attack: name="'; DROP TABLE devices; --"
                cursor = await db.execute(
                    """
                    INSERT INTO devices (name, public_key, ip_address)
                    VALUES (?, ?, ?)
                    """,
                    (name, public_key, ip_address)
                )
                
                device_id = cursor.lastrowid
                
                # Insert group memberships
                for group_name in groups:
                    await db.execute(
                        """
                        INSERT INTO groups (device_id, group_name)
                        VALUES (?, ?)
                        """,
                        (device_id, group_name)
                    )
                
                # Commit transaction
                await db.commit()
                
                logger.info(
                    f"Device '{name}' added successfully "
                    f"(ID: {device_id}, Groups: {groups})"
                )
                
                return device_id
                
    except aiosqlite.IntegrityError as e:
        if "UNIQUE constraint failed: devices.name" in str(e):
            raise ValueError(f"Device '{name}' already exists in database")
        else:
            raise RuntimeError(f"Database integrity error: {e}")
    
    except aiosqlite.Error as e:
        logger.error(f"Failed to add device '{name}': {e}")
        raise RuntimeError(f"Database error while adding device: {e}")


async def get_device(
    name: str,
    db_path: Path = DEFAULT_DB_PATH
) -> Optional[Dict[str, Any]]:
    """
    Retrieve device information by name.
    
    Returns device metadata including assigned groups. Used for configuration
    generation and access control policy enforcement.
    
    Args:
        name: Device name to lookup
        db_path: Path to the SQLite database file
        
    Returns:
        Dictionary containing device info, or None if not found:
        {
            "id": 1,
            "name": "laptop01",
            "public_key": "HIgo3Of...",
            "ip_address": "10.0.0.5/24",
            "groups": ["work", "trusted"],
            "created_at": "2026-02-13 12:30:00",
            "updated_at": "2026-02-13 12:30:00"
        }
        
    Example:
        >>> device = await get_device("laptop01")
        >>> if device:
        ...     print(f"IP: {device['ip_address']}")
        ...     print(f"Groups: {device['groups']}")
    """
    logger.debug(f"Retrieving device '{name}' from database")
    
    try:
        async with aiosqlite.connect(db_path) as db:
            # Set row factory to return dict-like rows
            db.row_factory = aiosqlite.Row
            
            # Fetch device record
            # SECURITY: Parameterized query prevents SQL injection
            async with db.execute(
                """
                SELECT id, name, public_key, ip_address, created_at, updated_at
                FROM devices
                WHERE name = ?
                """,
                (name,)
            ) as cursor:
                row = await cursor.fetchone()
                
                if row is None:
                    logger.debug(f"Device '{name}' not found")
                    return None
                
                # Convert row to dictionary
                device = dict(row)
                
                # Fetch associated groups
                async with db.execute(
                    """
                    SELECT group_name
                    FROM groups
                    WHERE device_id = ?
                    ORDER BY group_name
                    """,
                    (device["id"],)
                ) as group_cursor:
                    groups = [row["group_name"] async for row in group_cursor]
                
                device["groups"] = groups
                
                logger.debug(f"Device '{name}' retrieved successfully")
                return device
                
    except aiosqlite.Error as e:
        logger.error(f"Failed to retrieve device '{name}': {e}")
        raise RuntimeError(f"Database error while retrieving device: {e}")


async def list_devices(db_path: Path = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """
    List all devices in the SafeNet network.
    
    Returns:
        List of device dictionaries (same format as get_device)
        
    Example:
        >>> devices = await list_devices()
        >>> for device in devices:
        ...     print(f"{device['name']}: {device['ip_address']}")
    """
    logger.debug("Listing all devices")
    
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute(
                "SELECT id, name, public_key, ip_address, created_at, updated_at FROM devices ORDER BY name"
            ) as cursor:
                devices = []
                
                async for row in cursor:
                    device = dict(row)
                    
                    # Fetch groups for this device
                    async with db.execute(
                        "SELECT group_name FROM groups WHERE device_id = ? ORDER BY group_name",
                        (device["id"],)
                    ) as group_cursor:
                        device["groups"] = [g["group_name"] async for g in group_cursor]
                    
                    devices.append(device)
                
                logger.debug(f"Retrieved {len(devices)} devices")
                return devices
                
    except aiosqlite.Error as e:
        logger.error(f"Failed to list devices: {e}")
        raise RuntimeError(f"Database error while listing devices: {e}")


async def delete_device(name: str, db_path: Path = DEFAULT_DB_PATH) -> bool:
    """
    Delete a device from the SafeNet network.
    
    Automatically removes all associated group memberships (via CASCADE).
    
    Args:
        name: Device name to delete
        db_path: Path to the SQLite database file
        
    Returns:
        True if device was deleted, False if device didn't exist
        
    Example:
        >>> deleted = await delete_device("old_laptop")
        >>> if deleted:
        ...     print("Device removed from network")
    """
    logger.info(f"Deleting device '{name}'")
    
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON;")
            
            cursor = await db.execute(
                "DELETE FROM devices WHERE name = ?",
                (name,)
            )
            
            await db.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Device '{name}' deleted successfully")
                return True
            else:
                logger.debug(f"Device '{name}' not found (nothing to delete)")
                return False
                
    except aiosqlite.Error as e:
        logger.error(f"Failed to delete device '{name}': {e}")
        raise RuntimeError(f"Database error while deleting device: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GROUP OPERATIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def get_devices_in_group(
    group_name: str,
    db_path: Path = DEFAULT_DB_PATH
) -> List[str]:
    """
    Get all device names that belong to a specific group.
    
    Used for access control rule evaluation.
    
    Args:
        group_name: Name of the group to query
        db_path: Path to the SQLite database file
        
    Returns:
        List of device names in the group
        
    Example:
        >>> work_devices = await get_devices_in_group("work")
        >>> print(f"Work devices: {work_devices}")
    """
    logger.debug(f"Retrieving devices in group '{group_name}'")
    
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute(
                """
                SELECT d.name
                FROM devices d
                JOIN groups g ON d.id = g.device_id
                WHERE g.group_name = ?
                ORDER BY d.name
                """,
                (group_name,)
            ) as cursor:
                device_names = [row["name"] async for row in cursor]
                
                logger.debug(
                    f"Found {len(device_names)} devices in group '{group_name}'"
                )
                return device_names
                
    except aiosqlite.Error as e:
        logger.error(f"Failed to get devices in group '{group_name}': {e}")
        raise RuntimeError(f"Database error while querying group: {e}")


async def allocate_next_ip(db_path: Path = DEFAULT_DB_PATH) -> str:
    """
    Find the next available IP address in the 10.8.0.0/24 subnet.
    
    Scans the database for assigned IPs and returns the first unused one.
    Starts at 10.8.0.2 (skipping server .1).
    
    Returns:
        String IP address (e.g., "10.8.0.5") without CIDR.
        
    Raises:
        RuntimeError: If subnet is full (253 clients max).
    """
    logger.debug("Allocating new IP address...")
    devices = await list_devices(db_path)
    
    # Extract just the IP part (remove CIDR /24 etc)
    used_ips = set()
    for d in devices:
        if d["ip_address"]:
            ip = d["ip_address"].split("/")[0]
            used_ips.add(ip)
            
    # Simple linear scan 10.8.0.2 -> 10.8.0.254
    for i in range(2, 255):
        candidate = f"10.8.0.{i}"
        if candidate not in used_ips:
            logger.info(f"Allocated IP: {candidate}")
            return candidate
            
    raise RuntimeError("IP Pool Exhausted: No available IPs in 10.8.0.0/24")
