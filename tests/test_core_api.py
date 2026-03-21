import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_token_generation_success(async_client: AsyncClient):
    """Test successful JWT token generation."""
    response = await async_client.post(
        "/api/token",
        json={"username": "admin", "password": "safenet_admin_2026"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_auth_dependency_failure(async_client: AsyncClient):
    """Test that secured endpoints fail without a valid token."""
    response = await async_client.get("/api/devices")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.asyncio
async def test_valid_peer_enrollment(async_client: AsyncClient, auth_headers: dict):
    """Test complete flow: enroll peer and verify DB write."""
    payload = {
        "device_name": "test_peer_01",
        "device_type": "windows",
        "owner": "Test User"
    }
    
    # Enroll peer
    response = await async_client.post(
        "/api/devices/enroll",
        json=payload,
        headers=auth_headers
    )
    
    # Assert successful enrollment
    assert response.status_code in [200, 201]  # Standard success or created
    data = response.json()
    assert "private_key" in data
    assert "device_name" in data
    assert "assigned_ip" in data
    assert "public_key" in data
    assert "config_string" in data
    
    # Verify peer is in database
    list_response = await async_client.get(
        "/api/devices",
        headers=auth_headers
    )
    assert list_response.status_code == 200
    peers = list_response.json()
    assert any(p["name"] == "test_peer_01" for p in peers)
