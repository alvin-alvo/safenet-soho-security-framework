# SafeNet API Contract

## Overview
This document defines the interface between the SafeNet backend (FastAPI) and the frontend application.
All data is exchanged in **JSON** format.

### Base URL
`http://localhost:8000`

> [!NOTE]
> **Backend Requirement**
> The local API server must be running with **Administrator Privileges** to perform network operations (start/stop tunnel). If the server was started without admin rights, endpoints will return 500 errors.

### Authentication
All endpoints (except `/api/token` and `/api/health`) require a **JWT Bearer Token**.
- Header: `Authorization: Bearer <access_token>`

### Common Error Codes
- **401 Unauthorized**: Missing or invalid JWT token.
- **403 Forbidden**: Valid token but insufficient privileges (Admin required).
- **422 Validation Error**: Malformed JSON or invalid data types.
- **500 Internal Server Error**: Unhandled backend exception.

---

## 1. Authentication

### **Login (Get Token)**
**POST** `/api/token`

**Request:**
```json
{
  "username": "admin",
  "password": "your_password"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

---

## 2. Network Management

### **Start Tunnel**
**POST** `/api/network/start`
_Requires Admin Privileges_

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Tunnel started with 5 enrolled devices",
  "operation": "start"
}
```

**Response (500 Error):**
```json
{
  "detail": "Tunnel start failed: WireGuard service not found"
}
```

### **Stop Tunnel**
**POST** `/api/network/stop`

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Tunnel stopped successfully",
  "operation": "stop"
}
```

### **Get Tunnel Status**
**GET** `/api/status`

**Response (200 OK):**
```json
{
  "status": "active",        // "active" | "inactive"
  "service_state": "4",      // Windows Service State code
  "message": "Tunnel is running"
}
```

---

## 3. Device Management

### **List All Devices**
**GET** `/api/devices`

**Response (200 OK):**
```json
{
  "devices": [
    {
      "name": "iphone-15",
      "ip_address": "10.0.0.2",
      "public_key": "xCy...",
      "endpoint": "192.168.1.50:51820",
      "latest_handshake": 1707901234,  // Unix Timestamp
      "transfer_rx": 102400,           // Bytes received
      "transfer_tx": 204800,           // Bytes sent
      "is_active": true                // True if handshake < 5 mins ago
    }
  ],
  "count": 1
}
```

### **Enroll New Device**
**POST** `/api/devices/enroll`

**Request:**
```json
{
  "device_name": "ipad-pro"
}
```
_Constraint: `device_name` must be alphanumeric (hyphens/underscores allowed) and unique._

**Response (200 OK):**
```json
{
  "device_name": "ipad-pro",
  "assigned_ip": "10.0.0.3/24",
  "public_key": "zYx...",
  "private_key": "aBc...",          // EPHEMERAL: Display ONCE then discard
  "config_string": "[Interface]\n..." // Full WireGuard config file content
}
```

**Response (409 Conflict):**
```json
{
  "detail": "Device 'ipad-pro' already exists"
}
```

### **Remove Device**
**DELETE** `/api/devices/{device_name}`

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Device 'ipad-pro' removed successfully"
}
```

**Response (404 Not Found):**
```json
{
  "detail": "Device 'ipad-pro' not found"
}
```

---

## 4. System

### **Health Check**
**GET** `/api/health`
_No Authentication Required_

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "SafeNet API"
}
```
