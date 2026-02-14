"""
SafeNet CLI - Beautiful Command-Line Dashboard (Phase 5 + 5.1 UX Enhancements)

A stunning, color-coded Typer CLI for managing the SafeNet Zero-Trust Gateway.
Uses rich library for beautiful terminal output, tables, panels, and spinners.

Commands:
- status: Check gateway health and status
- start: Start the WireGuard tunnel gateway
- stop: Stop the WireGuard tunnel gateway  
- enroll <device_name>: Enroll a new device and generate QR code
- list: List all devices with live connection status
- remove <device_name>: Remove a device from the network

Author: SafeNet Security Team
License: GPL-3.0
"""

import sys
import os
import time
import typer
import requests
import qrcode
from io import StringIO
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime

# Add parent directory to path to allow importing core when run as script
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Initialize Typer app and Rich console
app = typer.Typer(
    help="SafeNet Zero-Trust Gateway Management CLI",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()

# API Configuration
API_URL = "http://127.0.0.1:8000"
CREDENTIALS = {
    "username": "admin",
    "password": "safenet_admin_2026"
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUTHENTICATION HELPER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_token() -> str:
    """
    Silently authenticate with the SafeNet API and retrieve JWT token.
    
    Returns:
        JWT access token for authenticated API requests
        
    Raises:
        typer.Exit: If authentication fails or API is unreachable
        
    Security:
        Uses hardcoded admin credentials (MVP only)
        Production should use secure credential storage
    """
    try:
        response = requests.post(
            f"{API_URL}/api/token",
            json=CREDENTIALS,
            timeout=5
        )
        
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            # Authentication failed (wrong credentials)
            console.print(Panel.fit(
                f"[bold red]✖ Authentication Failed[/bold red]\n\n"
                f"Status: {response.status_code}\n"
                f"Response: {response.text}",
                title="🚫 Auth Error",
                border_style="red"
            ))
            raise typer.Exit(code=1)
            
    except requests.exceptions.ConnectionError:
        # API server not running
        console.print(Panel.fit(
            "[bold red]FATAL ERROR:[/bold red] Could not connect to the SafeNet API.\n\n"
            "Is the FastAPI server running on [cyan]http://127.0.0.1:8000[/cyan]?\n\n"
            "[yellow]Start it with:[/yellow]\n"
            "[cyan]uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload[/cyan]",
            title="⚠️  Connection Timeout",
            border_style="red"
        ))
        raise typer.Exit(code=1)
        
    except requests.exceptions.Timeout:
        console.print(Panel.fit(
            "[bold red]Request Timeout[/bold red]\n\n"
            "The API server is not responding (timeout after 5 seconds).",
            title="⏱️  Timeout Error",
            border_style="red"
        ))
        raise typer.Exit(code=1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STATUS COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def status():
    """
    Check the SafeNet Gateway health and status.
    
    Displays color-coded gateway status:
    - [green]ONLINE[/green] if tunnel is active
    - [red]OFFLINE[/red] if tunnel is inactive
    - [yellow]UNKNOWN[/yellow] if status cannot be determined
    """
    console.print("\n[bold cyan]🔍 Checking SafeNet Gateway Status...[/bold cyan]\n")
    
    with console.status("[bold yellow]Querying API...", spinner="dots"):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Check health endpoint (unprotected)
        health_response = requests.get(f"{API_URL}/api/health", timeout=5)
        
        # Check status endpoint (protected)
        status_response = requests.get(f"{API_URL}/api/status", headers=headers, timeout=5)
    
    # Parse responses
    if health_response.status_code == 200:
        health_data = health_response.json()
        api_status = health_data.get("status", "unknown")
        
        # Display API health
        if api_status == "healthy":
            console.print(f"[bold green]✓[/bold green] API Server: [green]HEALTHY[/green]")
        else:
            console.print(f"[bold yellow]⚠[/bold yellow] API Server: [yellow]{api_status.upper()}[/yellow]")
    else:
        console.print(f"[bold red]✖[/bold red] API Server: [red]ERROR ({health_response.status_code})[/red]")
    
    # Display tunnel status
    if status_response.status_code == 200:
        status_data = status_response.json()
        tunnel_status = status_data.get("status", "unknown")
        message = status_data.get("message", "No details available")
        
        if tunnel_status == "active":
            console.print(f"[bold green]✓[/bold green] Gateway: [green]ONLINE[/green]")
            console.print(f"  [dim]{message}[/dim]")
        elif tunnel_status == "inactive":
            console.print(f"[bold red]✖[/bold red] Gateway: [red]OFFLINE[/red]")
            console.print(f"  [dim]{message}[/dim]")
        else:
            console.print(f"[bold yellow]?[/bold yellow] Gateway: [yellow]UNKNOWN[/yellow]")
            console.print(f"  [dim]{message}[/dim]")
    else:
        console.print(f"[bold red]✖[/bold red] Gateway Status: [red]ERROR ({status_response.status_code})[/red]")
    
    console.print()  # Add blank line for spacing


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# START COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def start():
    """
    Ignite the SafeNet Windows Gateway.
    
    Requires Administrator Privileges!
    
    This command:
    - Generates server keypair
    - Loads enrolled devices as peers
    - Starts WireGuard tunnel service
    
    Note: Must run terminal as Administrator on Windows
    """
    console.print("\n[bold yellow]🔥 Igniting Zero-Trust Gateway...[/bold yellow]\n")
    
    with console.status("[bold yellow]Provisioning server keys and peer list...", spinner="dots"):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Start the tunnel
        response = requests.post(
            f"{API_URL}/api/network/start",
            headers=headers,
            timeout=30  # Tunnel start can take time
        )
    
    # Handle response
    if response.status_code == 200:
        data = response.json()
        message = data.get("message", "Tunnel started successfully")
        
        console.print(Panel.fit(
            f"[bold green]✔ SafeNet Gateway is ONLINE and actively routing.[/bold green]\n\n"
            f"[dim]{message}[/dim]",
            title="🚀 Gateway Started",
            border_style="green"
        ))
    else:
        error_detail = "Unknown error"
        try:
            error_detail = response.json().get("detail", response.text)
        except:
            error_detail = response.text
        
        console.print(Panel.fit(
            f"[bold red]✖ Error starting gateway:[/bold red]\n\n"
            f"{error_detail}\n\n"
            f"[yellow]Hint: Are you running this terminal as Administrator?[/yellow]\n"
            f"[yellow]Try: Right-Click → Run as Administrator[/yellow]",
            title="❌ Startup Failed",
            border_style="red"
        ))
        raise typer.Exit(code=1)
    
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STOP COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def stop():
    """
    Tear down the SafeNet Gateway.
    
    This command:
    - Stops WireGuard tunnel service
    - Clears ephemeral server keys from memory
    - Removes tunnel configuration
    """
    console.print("\n[bold yellow]🛑 Stopping Zero-Trust Gateway...[/bold yellow]\n")
    
    with console.status("[bold yellow]Tearing down tunnel...", spinner="dots"):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Stop the tunnel
        response = requests.post(
            f"{API_URL}/api/network/stop",
            headers=headers,
            timeout=15
        )
    
    # Handle response
    if response.status_code == 200:
        data = response.json()
        message = data.get("message", "Tunnel stopped successfully")
        
        console.print(Panel.fit(
            f"[bold green]✔ SafeNet Gateway is now OFFLINE.[/bold green]\n\n"
            f"[dim]{message}[/dim]",
            title="🛑 Gateway Stopped",
            border_style="green"
        ))
    else:
        error_detail = "Unknown error"
        try:
            error_detail = response.json().get("detail", response.text)
        except:
            error_detail = response.text
        
        console.print(Panel.fit(
            f"[bold red]✖ Error stopping gateway:[/bold red]\n\n"
            f"{error_detail}",
            title="❌ Stop Failed",
            border_style="red"
        ))
        raise typer.Exit(code=1)
    
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENROLL COMMAND (UPDATED Phase 5.1)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def enroll(
    device_name: str = typer.Argument(
        ...,
        help="Unique name for the new device (alphanumeric, hyphens, underscores)"
    )
):
    """
    Enroll a new device, assign an IP, and generate a scannable QR code.
    
    This command:
    - Generates WireGuard keys for the device
    - Assigns IP address from pool
    - Returns complete client configuration
    - Displays SCANNABLE QR code for mobile apps
    - Hot-reloads server (if running) to trust the new device
    
    Example:
        python cli/console.py enroll my-iphone-15
    """
    console.print(f"\n[bold cyan]📱 Enrolling Device: {device_name}[/bold cyan]\n")
    
    with console.status(
        f"[bold yellow]Provisioning cryptographic keys for {device_name}...",
        spinner="bouncingBar"
    ):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Enroll the device
        response = requests.post(
            f"{API_URL}/api/devices/enroll",
            headers=headers,
            json={"device_name": device_name},
            timeout=15
        )
    
    # Handle response
    if response.status_code == 200:
        data = response.json()
        
        # Create beautiful table with device credentials
        table = Table(
            title=f"Device Provisioned: [bold cyan]{device_name}[/bold cyan]",
            border_style="cyan",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Attribute", style="magenta", justify="right", width=15)
        table.add_column("Value", style="cyan", no_wrap=False)
        
        # Add rows
        table.add_row("Device Name", data['device_name'])
        table.add_row("Assigned IP", f"[bold green]{data['assigned_ip']}[/bold green]")
        table.add_row("Public Key", data['public_key'])
        table.add_row("Private Key", "[dim](ephemeral - included in QR code)[/dim]")
        
        console.print("\n")
        console.print(table)
        console.print("\n")
        
        # Save config to file (better for Windows PowerShell)
        console.print("[bold cyan]💾 WireGuard Configuration:[/bold cyan]\n")
        
        try:
            # Clean the config string (replace escaped newlines)
            clean_config = data['config_string'].replace('\\n', '\n')
            
            # Save to file for easy import
            from pathlib import Path
            config_dir = Path('wg_configs')
            config_dir.mkdir(exist_ok=True)
            config_file = config_dir / f"{data['device_name']}.conf"
            with open(config_file, 'w') as f:
                f.write(clean_config)
            console.print(f"✔ Saved to: [bold green]{config_file.absolute()}[/bold green]\n")
            console.print("[dim]• Transfer file to mobile or import on desktop[/dim]\n")
            console.print("[bold cyan]📲 Or scan QR Code:[/bold cyan]\n")
            
            # Generate QR code in ASCII format (Windows PowerShell compatible)
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,
                border=2,
            )
            qr.add_data(clean_config)
            qr.make(fit=True)
            
            # Print as ASCII using Unicode blocks (works in PowerShell)
            qr.print_ascii(invert=True)
            
        except Exception as e:
            console.print(f"[yellow]⚠  QR Code generation failed: {e}[/yellow]")
            console.print(f"\n[dim]Config String:[/dim]\n{data['config_string']}")
        
        console.print("\n[bold green]✔ Device enrolled successfully![/bold green]")
        console.print("[dim]The server has been hot-reloaded to trust this device.[/dim]\n")
        
    elif response.status_code == 409:
        # Device already exists
        error_data = response.json()
        console.print(Panel.fit(
            f"[bold yellow]⚠  Device Already Exists[/bold yellow]\n\n"
            f"{error_data.get('detail', 'This device name is already enrolled.')}\n\n"
            f"[dim]Try a different device name or delete the existing device first.[/dim]",
            title="⚠️  Conflict",
            border_style="yellow"
        ))
        raise typer.Exit(code=1)
        
    elif response.status_code == 422:
        # Validation error (invalid device name)
        error_data = response.json()
        console.print(Panel.fit(
            f"[bold red]✖ Invalid Device Name[/bold red]\n\n"
            f"Device names must:\n"
            f"  • Be 3-20 characters long\n"
            f"  • Contain only letters, numbers, hyphens, and underscores\n"
            f"  • Not contain spaces or special characters\n\n"
            f"[yellow]Your input:[/yellow] [cyan]{device_name}[/cyan]",
            title="❌ Validation Error",
            border_style="red"
        ))
        raise typer.Exit(code=1)
        
    else:
        # Other errors
        error_detail = "Unknown error"
        try:
            error_detail = response.json().get("detail", response.text)
        except:
            error_detail = response.text
        
        console.print(Panel.fit(
            f"[bold red]✖ Enrollment Failed[/bold red]\n\n"
            f"Status: {response.status_code}\n"
            f"Error: {error_detail}",
            title="❌ Enrollment Error",
            border_style="red"
        ))
        raise typer.Exit(code=1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LIST COMMAND (NEW Phase 5.1)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def list():
    """
    List all devices with live connection status.
    
    Displays a table showing:
    - Device Name
    - Assigned IP
    - Public Key (truncated)
    - Status: Active (<3min), Disconnected (>3min), Provisioned (never)
    
    Connection status is determined by the latest WireGuard handshake timestamp.
    """
    console.print("\n[bold cyan]📋 Enrolled Devices[/bold cyan]\n")
    
    with console.status("[bold yellow]Fetching device list and handshake data...", spinner="dots"):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Fetch all devices from database
        devices_response = requests.get(
            f"{API_URL}/api/devices",
            headers=headers,
            timeout=10
        )
        
        # Fetch active handshakes from WireGuard
        try:
            active_response = requests.get(
                f"{API_URL}/api/devices/active",
                headers=headers,
                timeout=10
            )
            active_peers = active_response.json().get("active_peers", []) if active_response.status_code == 200 else []
        except:
            active_peers = []
    
    if devices_response.status_code != 200:
        console.print(Panel.fit(
            f"[bold red]✖ Failed to fetch devices[/bold red]\n\n"
            f"Status: {devices_response.status_code}",
            title="❌ Error",
            border_style="red"
        ))
        raise typer.Exit(code=1)
    
    devices = devices_response.json().get("devices", [])
    
    if not devices:
        console.print("[yellow]No devices enrolled yet.[/yellow]\n")
        console.print("[dim]Enroll your first device with:[/dim]")
        console.print("[cyan]python cli/console.py enroll my-device[/cyan]\n")
        return
    
    # Build handshake lookup by public key
    handshake_map = {peer["public_key"]: peer["latest_handshake"] for peer in active_peers}
    
    # Create beautiful table
    table = Table(
        title=f"[bold cyan]Enrolled Devices ({len(devices)} total)[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("Name", style="white", width=20)
    table.add_column("IP", style="cyan", width=15)
    table.add_column("Public Key", style="dim cyan", width=25)
    table.add_column("Status", style="white", width=20)
    
    # Add device rows with status logic
    current_time = int(time.time())
    
    for device in devices:
        # API returns "name" not "device_name"
        name = device.get("name", device.get("device_name", "Unknown"))
        ip = device.get("ip_address", "Unknown")
        pub_key = device.get("public_key", "Unknown")
        if len(pub_key) > 22:
            pub_key = pub_key[:22] + "..."  # Truncate for display
        
        # Get handshake timestamp
        last_handshake = handshake_map.get(device.get("public_key", ""), 0)
        
        # Calculate status
        if last_handshake == 0:
            status = "[yellow]Provisioned (Offline)[/yellow]"
        else:
            time_since_handshake = current_time - last_handshake
            if time_since_handshake < 180:  # < 3 minutes
                status = "[bold green]✓ Active[/bold green]"
            else:
                status = "[red]✖ Disconnected[/red]"
        
        table.add_row(name, ip, pub_key, status)
    
    console.print("\n")
    console.print(table)
    console.print("\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REMOVE COMMAND (NEW Phase 5.1)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.command()
def remove(
    device_name: str = typer.Argument(
        ...,
        help="Name of the device to remove"
    )
):
    """
    Remove a device from the network.
    
    This command:
    - Deletes the device from the database
    - Hot-reloads the server to drop the peer (if running)
    - Revokes network access immediately
    
    Example:
        python cli/console.py remove old-phone
    """
    console.print(f"\n[bold yellow]Removing Device: {device_name}[/bold yellow]\n")
    
    # Confirm deletion
    confirm = typer.confirm(f"Are you sure you want to remove '{device_name}'?")
    
    if not confirm:
        console.print("[yellow]Operation cancelled.[/yellow]\n")
        raise typer.Exit(code=0)
    
    with console.status(f"[bold yellow]Deleting device and updating server...", spinner="dots"):
        # Get JWT token
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Delete the device
        response = requests.delete(
            f"{API_URL}/api/devices/{device_name}",
            headers=headers,
            timeout=15
        )
    
    # Handle response
    if response.status_code == 200:
        data = response.json()
        message = data.get("message", f"Device '{device_name}' removed")
        
        console.print(Panel.fit(
            f"[bold green]Device Removed Successfully[/bold green]\n\n"
            f"[dim]{message}[/dim]\n\n"
            f"[dim]The server has been hot-reloaded (if running).[/dim]",
            title="Removal Complete",
            border_style="green"
        ))
        console.print()
        
    elif response.status_code == 404:
        # Device not found
        error_data = response.json()
        default_msg = f"Device '{device_name}' does not exist."
        detail = error_data.get('detail', default_msg)
        
        console.print(Panel.fit(
            f"[bold yellow]Device Not Found[/bold yellow]\n\n"
            f"{detail}\n\n"
            f"[dim]Use 'list' command to see enrolled devices.[/dim]",
            title="Not Found",
            border_style="yellow"
        ))
        raise typer.Exit(code=1)
        
    else:
        # Other errors
        error_detail = "Unknown error"
        try:
            error_detail = response.json().get("detail", response.text)
        except:
            error_detail = response.text
        
        console.print(Panel.fit(
            f"[bold red]Removal Failed[/bold red]\n\n"
            f"Status: {response.status_code}\n"
            f"Error: {error_detail}",
            title="Removal Error",
            border_style="red"
        ))
        raise typer.Exit(code=1)


@app.command()
def list():
    """List all enrolled devices and their status."""
    console.print(Panel("[bold cyan]Network Devices[/bold cyan]", border_style="cyan"))

    devices = []
    with console.status("[bold green]Fetching device list...", spinner="dots"):
        try:
            token = get_token()
            response = requests.get(
                f"{API_URL}/api/devices",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if response.status_code != 200:
                console.print(f"[bold red]Failed to fetch devices: {response.text}[/bold red]")
                raise typer.Exit(code=1)
                
            data = response.json()
            devices = data.get("devices", [])
            
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            raise typer.Exit(code=1)

    if not devices:
        console.print(Panel("[yellow]No devices enrolled yet.[/yellow]", border_style="yellow"))
        return

    # Build Table
    table = Table(title=None, box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Status", justify="center")
    table.add_column("Device Name", style="white")
    table.add_column("IP Address", style="green")
    table.add_column("Endpoint", style="dim")
    table.add_column("Last Handshake", justify="right")
    table.add_column("Data (Rx/Tx)", justify="right")

    for device in devices:
        name = device.get("name")
        ip = device.get("ip_address")
        endpoint = device.get("endpoint") or "N/A"
        handshake_ts = device.get("latest_handshake", 0)
        rx = device.get("transfer_rx", 0)
        tx = device.get("transfer_tx", 0)
        is_active = device.get("is_active", False)
        
        # Status Icon
        status_icon = "+" if is_active else "-"
        status_text = "[green]Online[/green]" if is_active else "[red]Offline[/red]"
        
        # Handshake formatting
        if handshake_ts > 0:
            handshake_dt = datetime.fromtimestamp(handshake_ts)
            handshake_str = handshake_dt.strftime("%H:%M:%S")
            # Calculate ago
            ago = int(time.time() - handshake_ts)
            if ago < 60:
                handshake_str += f" ({ago}s ago)"
            elif ago < 3600:
                handshake_str += f" ({ago//60}m ago)"
            else:
                hours = ago // 3600
                if hours > 24:
                    handshake_str = f"{hours//24}d ago"
                else:
                    handshake_str += f" ({hours}h ago)"
        else:
            handshake_str = "[dim]Never[/dim]"
            
        # Data formatting
        def fmt_bytes(b):
            for unit in ["B", "KB", "MB", "GB"]:
                if b < 1024:
                    return f"{b:.1f}{unit}"
                b /= 1024
            return f"{b:.1f}TB"
            
        data_str = f"In:{fmt_bytes(rx)} / Out:{fmt_bytes(tx)}"

        table.add_row(
            f"{status_icon} {status_text}",
            name,
            ip,
            endpoint,
            handshake_str,
            data_str
        )

    console.print(table)
    console.print(f"[dim]Total: {len(devices)} devices[/dim]\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    import sys
    import os
    
    # Add project root to path to allow importing core
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    sys.path.insert(0, project_root)

    from core.utils import is_admin
    import ctypes

    
    # Auto-elevate if not admin
    if not is_admin():
        # Re-run the script with Admin privileges
        try:
            print("Requesting Administrator privileges...")
            params = " ".join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
            print("Please run this terminal as Administrator.")
            sys.exit(1)
            
    app()
