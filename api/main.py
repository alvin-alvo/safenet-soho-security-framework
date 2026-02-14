"""
SafeNet API - Main Application

FastAPI application initialization and configuration.

Features:
- JWT-based authentication
- CORS middleware for local testing
- Swagger UI documentation
- Async request handling
- Centralized logging

Usage:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Author: SafeNet Security Team
License: GPL-3.0
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import sys
import asyncio

# FIX: Force ProactorEventLoop on Windows for subprocess support (Uvicorn uses Selector by default)
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from api.routes import router
from core import init_db


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGGING CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LIFESPAN CONTEXT MANAGER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    
    Startup:
        - Initialize database
        - Check WireGuard installation
        
    Shutdown:
        - Close database connections
        - Log shutdown
    """
    # Startup
    logger.info("=" * 70)
    logger.info("SafeNet API Starting Up")
    logger.info("=" * 70)
    
    # Check Admin Privileges
    from core.utils import is_admin
    if not is_admin():
        logger.critical("API SERVER MUST BE RUN AS ADMINISTRATOR")
        logger.critical("WireGuard tunnel management requires elevated privileges.")
        logger.critical("Please stop the server and restart it in an Administrator terminal.")
        # We don't exit here to allow read-only operations, but key features will fail
        print("\n\n" + "!"*80)
        print("CRITICAL ERROR: NOT RUNNING AS ADMINISTRATOR")
        print("WireGuard tunnel operations WILL fail.")
        print("Please restart uvicorn in an Administrator terminal.")
        print("!"*80 + "\n\n")

    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    logger.info("API ready to accept connections")
    logger.info("=" * 70)
    
    yield
    
    # Shutdown
    logger.info("SafeNet API shutting down...")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FASTAPI APPLICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app = FastAPI(
    title="SafeNet API",
    description="""
    **SafeNet Zero-Trust Micro-Perimeter Framework API**
    
    This API provides secure access to SafeNet's WireGuard-based zero-trust network.
    
    ## Features
    
    -  **JWT Authentication**: Secure token-based authentication
    -  **Device Enrollment**: Generate WireGuard configurations
    -  **Network Management**: Start/stop tunnels remotely
    -  **Status Monitoring**: Real-time tunnel status
    
    ## Authentication
    
    1. Obtain a JWT token from `/api/token`
    2. Include the token in the `Authorization` header:
       ```
       Authorization: Bearer <your_token_here>
       ```
    
    ## Security
    
    - All endpoints (except `/api/token` and `/api/health`) require JWT authentication
    - Input validation prevents injection attacks
    - Private keys are never stored (ephemeral)
    
    ## Support
    
    - GitHub: https://github.com/alvin-alvo/safenet-soho-security-framework
    - License: GPL-3.0
    """,
    version="0.4.0",
    contact={
        "name": "SafeNet Security Team",
        "url": "https://github.com/alvin-alvo/safenet-soho-security-framework",
    },
    license_info={
        "name": "GPL-3.0",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
    },
    lifespan=lifespan
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CORS MIDDLEWARE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React/Flutter dev server
        "http://localhost:8080",  # Alternative dev port
        "http://192.168.137.*",   # Windows Mobile Hotspot IP range
        "*"  # Allow all for MVP (REMOVE IN PRODUCTION)
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

logger.info("CORS middleware configured for local development")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ROUTE REGISTRATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.include_router(router)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ROOT ENDPOINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint - API information.
    
    Returns:
        API metadata and links
    """
    return {
        "service": "SafeNet API",
        "version": "0.4.0",
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json"
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EXCEPTION HANDLERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.exception_handler(404)
async def not_found_handler(request, exc):
    """
    Custom 404 handler.
    """
    return JSONResponse(
        status_code=404,
        content={
            "detail": "Endpoint not found",
            "path": str(request.url)
        }
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """
    Custom 500 handler.
    """
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": "Please check server logs for details"
        }
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEVELOPMENT ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


if __name__ == "__main__":
    import uvicorn
    
    print()
    print("=" * 70)
    print("SafeNet API - Development Server")
    print("=" * 70)
    print()
    print("API Documentation: http://localhost:8000/docs")
    print("Alternative Docs:  http://localhost:8000/redoc")
    print()
    print("Default Credentials:")
    print("  Username: admin")
    print("  Password: safenet_admin_2026")
    print()
    print("=" * 70)
    print()
    
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",  # Accessible from Windows hotspot
        port=8000,
        reload=True,     # Auto-reload on code changes
        log_level="info"
    )
