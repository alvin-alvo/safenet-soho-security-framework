
import asyncio
import logging
import sys
import os

# Add parent directory to path to allow importing core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.engine import get_tunnel_status

# Configure logging
logging.basicConfig(level=logging.INFO)

async def test():
    print("Testing get_tunnel_status()...")
    status = await get_tunnel_status()
    print(f"Status: {status}")

if __name__ == "__main__":
    asyncio.run(test())
