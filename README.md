# SafeNet SOHO Security Framework

SafeNet is a Zero-Trust Network Access (ZTNA) framework for Small Office/Home Office (SOHO) environments. It provides a secure, identity-aware VPN overlay using WireGuard, managed by a modern Python backend and CLI.

## Architecture

The system operates on a Hub-and-Spoke topology:
- **Control Plane**: A FastAPI backend managing identity, key exchange, and policy.
- **Data Plane**: Native WireGuard kernel interface for high-performance routing.
- **Management**: A Typer-based CLI for administration.

## Directory Structure

```
safenet-soho-security-framework/
├── api/                        # FastAPI Definitions
│   ├── routes.py               # Endpoint Logic
│   └── auth.py                 # JWT Authentication
├── core/                       # Business Logic Layer
│   ├── engine.py               # WireGuard Interface Management
│   ├── keygen.py               # Cryptographic Operations
│   └── db.py                   # Async SQLite Database
├── cli/                        # Command Line Interface
│   └── console.py              # Admin Dashboard
├── scripts/                    # Utility & Maintenance Scripts
├── docs/                       # Developer Documentation
├── data/                       # Persistent Configuration & DB
└── run_api.py                  # Server entry point
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:
- [API Contract](docs/FRONTEND_API_CONTRACT.md): Integration guide for frontend developers.
- [Architecture](docs/ARCHITECTURE.md): System design, cryptography, and database schema.
- [Setup Guide](docs/SETUP.md): Environment configuration and installation.
- [CLI Reference](docs/CLI_REFERENCE.md): Command usage and examples.
- [Testing Guide](docs/TESTING.md): Instructions for running manual and automated tests.

## Quick Start

### 1. One-Click Setup (Recommended)
Simply double-click:
1.  **`setup_env.bat`**: Installs Python environment and dependencies.
2.  **`run_server.bat`**: Starts the API Server (Will ask for Admin rights).

### 2. Manual Setup (Advanced)
If you prefer manual control:
```powershell
    python -m venv venv
    .\venv\Scripts\activate
    pip install -r requirements.txt
    python run_api.py
```

### 3. Manage the Gateway
Open a new terminal (Administrator):
```powershell
    python cli/console.py status
```
    ```powershell
    python cli/console.py status
    python cli/console.py start
    python cli/console.py enroll my-device
    ```

## License
GPL-3.0
