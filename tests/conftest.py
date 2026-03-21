import pytest
import pytest_asyncio
import os
import aiosqlite
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from api.main import app
from core import db

from pathlib import Path

# Use a local test database rather than system temp to avoid Windows Permission Errors
@pytest.fixture(scope="session")
def test_db_path():
    db_file = Path("test_safenet_pytest.db")
    if db_file.exists():
        db_file.unlink()
    return db_file

@pytest_asyncio.fixture(autouse=True)
async def setup_test_db(test_db_path, monkeypatch):
    """Patch the database path to use our test database and initialize it."""
    # Hijack aiosqlite.connect to ALWAYS point to our test database!
    # This prevents FastAPI endpoints from using the production data/safenet.db
    # which has already been bound as a default argument in core/db.py.
    original_connect = aiosqlite.connect
    
    def mock_connect(database, *args, **kwargs):
        # Ignore the requested path and forcefully substitute our isolated test DB
        return original_connect(test_db_path, *args, **kwargs)
        
    monkeypatch.setattr(aiosqlite, "connect", mock_connect) # Corrected to patch the module's connect function
    
    # Initialize the test database
    await db.init_db(test_db_path)
    
    yield
    
    # Teardown: delete the test database
    if test_db_path.exists():
        try:
            os.remove(test_db_path)
        except PermissionError:
            pass

@pytest_asyncio.fixture
async def async_client():
    """Create a test client for the FastAPI application."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.fixture
def auth_headers():
    """Return valid JWT authentication headers for testing."""
    from api.auth import create_access_token
    token = create_access_token({"sub": "admin"})
    return {"Authorization": f"Bearer {token}"}
