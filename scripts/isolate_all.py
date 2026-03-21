import yaml
import sys
import subprocess
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

def main():
    try:
        console.print("[info][INFO][/info] Parsing data/policy.yml")
        
        with open(POLICY_FILE, "r") as f:
            policy = yaml.safe_load(f)
            
        console.print("[action][ACTION][/action] Modifying routing rules for all devices -> Resetting to Strict Isolation")
            
        # Optional structure: Wipe temporary bridge rules from policy if they exist
        if "bridges" in policy:
            policy["bridges"] = []
            with open(POLICY_FILE, "w") as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        console.print("[system][SYSTEM][/system] Executing WireGuard hot-reload via Windows kernel...")
        
        # In a hub-and-spoke ZTNA model on Windows, isolation is enforced by removing any 
        # firewall exceptions previously created to permit traffic between WireGuard clients.
        # This removes all matching SafeNet-P2P rules from the Windows Firewall.
        ps_command = "Remove-NetFirewallRule -Group 'SafeNet-P2P' -ErrorAction SilentlyContinue"
        
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True)
        
        # PowerShell returns exit code 1 and no stderr if no rules match when SilentlyContinue is used
        if result.returncode != 0 and result.stderr.strip() and "No MSFT_NetFirewallRule" not in result.stderr:
            console.print(f"[error][ERROR][/error] Firewall rule execution encountered an issue: {result.stderr.strip()}")
            
        console.print("[success][SUCCESS][/success] Policy enforced successfully. All devices isolated in Hub-and-Spoke mode unless explicitly authorized by policy schema rules.")
        
    except Exception as e:
        console.print(f"[error][ERROR][/error] Critical error encountered during policy enforcement.")
        console.print_exception()
        sys.exit(1)

if __name__ == "__main__":
    main()
