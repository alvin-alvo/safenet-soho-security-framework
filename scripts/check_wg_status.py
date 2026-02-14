
import asyncio
import subprocess

async def check_wg():
    print("Checking 'wg show safenet'...")
    try:
        process = await asyncio.create_subprocess_exec(
            "wg", "show", "safenet",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        print(f"Return Code: {process.returncode}")
        print(f"Stdout: {stdout.decode().strip()}")
        print(f"Stderr: {stderr.decode().strip()}")
        
    except FileNotFoundError:
        print("wg command not found")

if __name__ == "__main__":
    asyncio.run(check_wg())
