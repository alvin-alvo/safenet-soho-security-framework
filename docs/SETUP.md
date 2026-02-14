# SafeNet Setup Guide

## Requirements
- **Windows OS**: Development relies on native Windows WireGuard implementation.
- **Python 3.10+**
- **Administrator Privileges**: Essential for `wg` command execution.
- **WireGuard**: Install from [wireguard.com/install](https://www.wireguard.com/install/)

## 1. Automated Setup (Recommended)

Run the included batch scripts for zero-hassle configuration.

### Step 1: Install Dependencies
Double-click **`setup_env.bat`**. This will:
- Check for Python.
- Create the virtual environment.
- Install all required libraries testing.

### Step 2: Start Server
Right-click **`run_server.bat`** and select **Run as Administrator**.
- Automatically activates the environment.
- Starts the API server with correct permissions.

---

## 2. Manual Setup (Developer)

### Create Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Install Dependencies
```powershell
pip install -r requirements.txt
```

### Start Server
*Must be run as Administrator.*
```powershell
python run_api.py
```

### Verifying Installation
Open `http://localhost:8000/docs` in your browser.

---

## 3. Running the CLI

Open a NEW terminal (also as Administrator) and activate the venv.

```powershell
python cli/console.py status
```
If the status check passes, your environment is correctly configured.
