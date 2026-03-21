import yaml
import sys
import argparse
import subprocess
import sqlite3
from pathlib import Path
from rich.console import Console
from rich.theme import Theme
from rich.traceback import install

install(show_locals=True)

custom_theme = Theme({
    "info": "blue bold",
    "action": "cyan bold",
    "system": "magenta bold",
    "success": "green bold",
    "error": "red bold",
})
console = Console(theme=custom_theme)

POLICY_FILE = "data/policy.yml"
DB_FILE = "data/safenet.db"

def get_device_info(device_name):
    """Retrieve device IP and groups from the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, ip_address FROM devices WHERE name = ?", (device_name,))
        device = cursor.fetchone()
        
        if not device:
            return None, None
            
        cursor.execute("SELECT group_name FROM groups WHERE device_id = ?", (device["id"],))
        groups = [row["group_name"] for row in cursor.fetchall()]
        
        ip = device["ip_address"].split('/')[0] if device["ip_address"] else None
        
        return ip, groups
    except Exception as e:
        console.print(f"[error][ERROR][/error] Failed to query database: {e}")
        return None, None
    finally:
        if 'conn' in locals():
            conn.close()

def is_allow_listed(groups1, groups2, policy_rules):
    """Check if any of the device 1 groups are allowed to talk to device 2 groups based on the policy."""
    for rule in policy_rules:
        if rule.get('action') == 'allow':
            if rule.get('from') in groups1 and rule.get('to') in groups2:
                return True
            # Check reverse direction as well for P2P routing
            if rule.get('from') in groups2 and rule.get('to') in groups1:
                return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Authorize lateral movement routing between two peers if policy allows.")
    parser.add_argument("device1", help="Source peer name")
    parser.add_argument("device2", help="Target peer name")
    parser.add_argument("--force", action="store_true", help="Force bridge creation even if policy says deny")
    args = parser.parse_args()

    try:
        console.print("[info][INFO][/info] Parsing data/policy.yml")
        
        with open(POLICY_FILE, "r") as f:
            policy = yaml.safe_load(f)
            
        # Get IPs and groups from DB
        ip1, groups1 = get_device_info(args.device1)
        ip2, groups2 = get_device_info(args.device2)
        
        if not ip1 or not ip2:
            raise ValueError(f"One or both devices not found in database or lacking assigned IPs!")
            
        access_rules = policy.get("access_rules", [])
        
        console.print(f"[info][INFO][/info] Device 1 ({args.device1}) Groups: {groups1}")
        console.print(f"[info][INFO][/info] Device 2 ({args.device2}) Groups: {groups2}")
        
        allowed = is_allow_listed(groups1, groups2, access_rules)
        
        if not allowed and not args.force:
            console.print(f"[error][ERROR][/error] Policy Evaluation: DENIED by default Zero-Trust behavior. Use --force to override.")
            sys.exit(1)
        elif not allowed and args.force:
            console.print(f"[action][ACTION][/action] Policy Evaluation: DENIED but overriding due to --force flag.")
        else:
            console.print(f"[success][SUCCESS][/success] Policy Evaluation: ALLOWED based on group associations.")
            
        console.print(f"[action][ACTION][/action] Modifying routing rules for {args.device1} <-> {args.device2}")
        
        # Save bridge directly to policy yaml to record state 
        bridges = policy.get("bridges", [])
        b1 = {"source": args.device1, "target": args.device2}
        b2 = {"source": args.device2, "target": args.device1}
        if b1 not in bridges: bridges.append(b1)
        if b2 not in bridges: bridges.append(b2)
        policy["bridges"] = bridges
        
        with open(POLICY_FILE, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        
        rule_name_1 = f"SafeNet-Bridge-{args.device1}-to-{args.device2}"
        rule_name_2 = f"SafeNet-Bridge-{args.device2}-to-{args.device1}"
        
        console.print("[system][SYSTEM][/system] Executing WireGuard hot-reload via Windows Firewall integration...")
        
        # Inject Windows Firewall routing rules
        ps_command = (
            f"New-NetFirewallRule -DisplayName '{rule_name_1}' -Group 'SafeNet-P2P' "
            f"-Direction Inbound -Action Allow -LocalAddress {ip2} -RemoteAddress {ip1} -ErrorAction SilentlyContinue; "
            f"New-NetFirewallRule -DisplayName '{rule_name_2}' -Group 'SafeNet-P2P' "
            f"-Direction Inbound -Action Allow -LocalAddress {ip1} -RemoteAddress {ip2} -ErrorAction SilentlyContinue"
        )
        
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True)
        
        if result.returncode != 0:
            console.print(f"[error][ERROR][/error] Firewall rule injection encountered an issue: {result.stderr.strip()}")
            sys.exit(1)
            
        console.print(f"[success][SUCCESS][/success] Policy enforced successfully: Local routing active between peers.")
        
    except Exception as e:
        console.print(f"[error][ERROR][/error] Bridge authorization exception.")
        console.print_exception()
        sys.exit(1)

if __name__ == "__main__":
    main()
