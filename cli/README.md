# SafeNet CLI

The Command Line Interface (CLI) is the primary administrative interface for the gateway.

> [!IMPORTANT]
> **Run as Administrator**
> All CLI commands should be executed from an Administrator terminal to ensure access to the WireGuard service.

## Implementation

Built using **Typer** and **Rich** for a modern, colorful, and user-friendly terminal experience.

-   **`console.py`**: The entry point. Defines all commands (`start`, `stop`, `status`, `enroll`, `list`).

## Architecture

The CLI acts as an **API Client**. It does not interact with the database or WireGuard directly (mostly).
1.  User runs `python cli/console.py start`
2.  CLI sends HTTP POST to `http://localhost:8000/api/network/start`
3.  API handles the logic and returns JSON.
4.  CLI formats the JSON into a beautiful table/message.

*Note*: Some commands (like `enroll`'s QR code generation or file saving) happen client-side after receiving keys from the API.
