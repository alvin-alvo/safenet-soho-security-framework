# SafeNet API

The REST API is the control plane for the Secure Network Gateway.

## Implementation

Built using **FastAPI** and **Uvicorn**.

## Files

-   **`main.py`**: Application factory. Configures Middleware (CORS), Logging, and Exception Handling.
-   **`routes.py`**: Defines all HTTP endpoints (`/api/token`, `/api/devices`, etc.).
-   **`auth.py`**: Authentication logic. Implements OAuth2 Password Bearer flow with JWT tokens.

## Running the Server

> [!CAUTION]
> **Administrator Privileges Required**
> The API server manages Windows Services. It **must** be run from an elevated terminal.

Do not run `main.py` directly. Use the root launcher:
```powershell
python run_api.py
```
This ensures the correct Windows Event Loop (`ProactorEventLoop`) is used for asynchronous subprocess support.
