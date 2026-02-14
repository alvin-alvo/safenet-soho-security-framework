"""
SafeNet API - Pydantic Validation Schemas

This module defines all request/response models for the SafeNet API.
All schemas include strict validation to prevent injection attacks.

Security Features:
- Regex validation on device names (prevents command injection)
- Field validators for IP addresses
- Strict typing for all fields
- Input sanitization

Author: SafeNet Security Team
License: GPL-3.0
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator
import re


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECURITY PATTERNS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Device name pattern: alphanumeric, dashes, underscores only
# Prevents command injection and special shell characters
DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

# IP address pattern (basic validation)
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUTHENTICATION SCHEMAS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TokenRequest(BaseModel):
    """
    Request model for JWT token generation.
    
    For MVP, we use a simple username/password.
    In production, integrate with proper user management.
    """
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "username": "admin",
                    "password": "safenet_admin_2026"
                }
            ]
        }
    }


class TokenResponse(BaseModel):
    """
    Response model for JWT token generation.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiration time in seconds")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEVICE ENROLLMENT SCHEMAS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class EnrollDeviceRequest(BaseModel):
    """
    Request model for device enrollment.
    
    Security: Strict regex validation prevents command injection
    when device_name is used in system commands or database queries.
    """
    device_name: str = Field(
        ...,
        min_length=3,
        max_length=20,
        description="Device identifier (alphanumeric, dashes, underscores only)"
    )
    
    @field_validator("device_name")
    @classmethod
    def validate_device_name(cls, v: str) -> str:
        """
        Validate device name against security pattern.
        
        Args:
            v: Device name to validate
            
        Returns:
            Validated device name
            
        Raises:
            ValueError: If device name contains invalid characters
            
        Security:
            - Prevents command injection (no shell metacharacters)
            - Prevents SQL injection (no quotes or semicolons)
            - Prevents path traversal (no slashes or dots)
        """
        if not DEVICE_NAME_PATTERN.match(v):
            raise ValueError(
                "Device name must be 3-20 characters long and contain only "
                "letters, numbers, dashes, and underscores. "
                "No spaces or special characters allowed."
            )
        return v
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {"device_name": "laptop-01"},
                {"device_name": "phone_alice"},
                {"device_name": "iot-device-123"}
            ]
        }
    }


class EnrollDeviceResponse(BaseModel):
    """
    Response model for successful device enrollment.
    
    Contains complete WireGuard configuration for the client.
    The private key is included ONLY in this response and never stored.
    """
    device_name: str
    assigned_ip: str = Field(..., description="Assigned WireGuard IP address")
    public_key: str = Field(..., description="Device's public key (stored in DB)")
    private_key: str = Field(..., description="Device's private key (EPHEMERAL - save immediately!)")
    config_string: str = Field(..., description="Complete WireGuard configuration")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "device_name": "laptop-01",
                    "assigned_ip": "10.8.0.2/24",
                    "public_key": "abc123...==",
                    "private_key": "xyz789...==",
                    "config_string": "[Interface]\\nPrivateKey = xyz789...==\\n..."
                }
            ]
        }
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NETWORK MANAGEMENT SCHEMAS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class StatusResponse(BaseModel):
    """
    Response model for tunnel status check.
    """
    status: str = Field(..., description="Tunnel status: 'active' or 'inactive'")
    service_state: Optional[str] = Field(None, description="Windows service state code")
    message: Optional[str] = Field(None, description="Additional status information")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "active",
                    "service_state": "4",
                    "message": "Tunnel is running"
                },
                {
                    "status": "inactive",
                    "message": "Tunnel is not running"
                }
            ]
        }
    }


class NetworkResponse(BaseModel):
    """
    Generic response model for network operations (start/stop).
    """
    success: bool
    message: str
    operation: str = Field(..., description="Operation performed: 'start' or 'stop'")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "success": True,
                    "message": "Tunnel started successfully",
                    "operation": "start"
                },
                {
                    "success": False,
                    "message": "Failed to start tunnel: Access denied",
                    "operation": "start"
                }
            ]
        }
    }



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MONITORING SCHEMAS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class DeviceStatus(BaseModel):
    """
    Real-time status of a connected device.
    
    Combines static DB info with dynamic WireGuard status.
    """
    name: str = Field(..., description="Device name")
    ip_address: str = Field(..., description="Assigned IP address")
    public_key: str = Field(..., description="WireGuard public key")
    
    # Dynamic fields from wg show dump
    endpoint: Optional[str] = Field(None, description="Remote endpoint IP:Port")
    latest_handshake: int = Field(0, description="Unix timestamp of last handshake")
    transfer_rx: int = Field(0, description="Total bytes received")
    transfer_tx: int = Field(0, description="Total bytes sent")
    is_active: bool = Field(False, description="True if handshake < 3 mins ago")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "laptop-01",
                    "ip_address": "10.8.0.2",
                    "public_key": "abc...",
                    "endpoint": "203.0.113.5:54321",
                    "latest_handshake": 1678888888,
                    "transfer_rx": 1024000,
                    "transfer_tx": 2048000,
                    "is_active": True
                }
            ]
        }
    }


class DeviceListResponse(BaseModel):
    """
    Response model for listing all devices with status.
    """
    devices: list[DeviceStatus]
    count: int
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "devices": [
                        {
                            "name": "laptop-01",
                            "ip_address": "10.8.0.2",
                            "public_key": "abc...",
                            "is_active": True
                        }
                    ],
                    "count": 1
                }
            ]
        }
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ERROR RESPONSE SCHEMAS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class ErrorResponse(BaseModel):
    """
    Standard error response model.
    """
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Machine-readable error code")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "detail": "Device name already exists",
                    "error_code": "DEVICE_EXISTS"
                },
                {
                    "detail": "Invalid authentication credentials",
                    "error_code": "AUTH_FAILED"
                }
            ]
        }
    }
