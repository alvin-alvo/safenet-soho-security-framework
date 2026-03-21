import pytest
import asyncio
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_simultaneous_enrollments(async_client: AsyncClient, auth_headers: dict):
    """
    Fires 200 simultaneous enrollment requests at the FastAPI endpoint.
    Ensures the database does not lock and WireGuard hot-reload queue processes cleanly.
    """
    
    async def enroll_peer(index: int):
        payload = {
            "device_name": f"stress_peer_{index}",
            "device_type": "linux",
            "owner": "Stress Test"
        }
        res = await async_client.post(
            "/api/devices/enroll",
            json=payload,
            headers=auth_headers
        )
        return res
        
    # Create 200 concurrent tasks
    tasks = [enroll_peer(i) for i in range(200)]
    
    # Execute all at once
    results = await asyncio.gather(*tasks)
    
    # Verify all 200 succeeded without Database Locking (SQLite concurrent write issues)
    success_count = 0
    for response in results:
        if response.status_code in [200, 201]:
            data = response.json()
            if "config_string" in data:
                success_count += 1
                
    assert success_count == 200, f"Expected 200 successful enrollments, got {success_count}. DB Lock likely occurred."
    
    # Verify database state has 200 total new peers
    list_res = await async_client.get("/api/peers", headers=auth_headers)
    assert list_res.status_code == 200
    peers = list_res.json()
    
    stress_peers_in_db = [p for p in peers if p["name"].startswith("stress_peer_")]
    assert len(stress_peers_in_db) == 200
