
import os
import sys
import ctypes
import subprocess
from pathlib import Path

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def check_config():
    print("🔍 Checking WireGuard Configuration...")
    
    # 1. Check Admin
    if not is_admin():
        print("    ⚠  ERROR: Must run as Administrator to read ProgramData config!")
        return

    # 2. Check Directories
    program_data = os.environ.get("ProgramData", "C:\\ProgramData")
    safenet_dir = Path(program_data) / "SafeNet"
    config_file = safenet_dir / "safenet-vpn.conf"
    
    print(f"  • Config File: {config_file}")
    
    if not config_file.exists():
        print("    ❌ Config file NOT FOUND!")
        return

    print("\n📄 Config Content:")
    print("-" * 40)
    try:
        content = config_file.read_text(encoding="utf-8")
        print(content)
    except Exception as e:
        print(f"    ❌ Failed to read config: {e}")
    print("-" * 40)

    # 3. Check Firewall
    print("\n🔥 Checking Firewall Rules...")
    try:
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        # This produces too much output, let's look for specific port 65065
        # actually, wireguard usually creates rules for the executable
        
        # subprocess.run(cmd) 
        print("  • Skipped (too verbose). Assuming WireGuard handled it.")
    except:
        pass

if __name__ == "__main__":
    check_config()
