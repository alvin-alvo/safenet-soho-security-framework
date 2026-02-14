
import asyncio
import re
from pathlib import Path
import os
import sys

# Mock imports
def get_program_data_dir():
    program_data = os.environ.get("ProgramData", "C:\\ProgramData")
    safenet_dir = os.path.join(program_data, "SafeNet")
    return safenet_dir

async def derive_public_key(private_key: str) -> str:
    print(f"DEBUG: Deriving pubkey for privkey length {len(private_key)}")
    try:
        proc_public = await asyncio.create_subprocess_exec(
            "wg", "pubkey",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc_public.communicate(input=(private_key + '\n').encode('utf-8'))
        
        if proc_public.returncode != 0:
            print(f"ERROR: wg pubkey failed: {stderr.decode()}")
            return None
        return stdout.decode().strip()
    except Exception as e:
        print(f"ERROR: Exception in derive: {e}")
        return None

async def test_keys():
    print("--- Testing get_persistent_server_keys ---")
    
    config_dir = Path(get_program_data_dir())
    config_file = config_dir / "safenet-vpn.conf"
    
    print(f"Config path: {config_file}")
    
    if not config_file.exists():
        print("❌ Config file not found")
        return
        
    content = config_file.read_text(encoding="utf-8")
    print(f"\n[Raw Content Start]\n{content[:100]}...\n[Raw Content End]\n")
    
    # Test Regex
    match = re.search(r"PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)", content)
    if match:
        priv = match.group(1).strip()
        print(f"✅ Regex matched PrivateKey: {priv[:5]}...{priv[-5:]} (Len: {len(priv)})")
        
        # Test Derivation
        pub = await derive_public_key(priv)
        if pub:
            print(f"✅ Derived PublicKey: {pub}")
        else:
            print("❌ Failed to derive public key")
    else:
        print("❌ Regex failed to match PrivateKey")
        print(f"Regex used: r'PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)'")

if __name__ == "__main__":
    asyncio.run(test_keys())
