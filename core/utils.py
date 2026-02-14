
import ctypes
import os
import sys

def is_admin():
    """Check if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_program_data_dir():
    """Get the robust ProgramData directory for config storage."""
    program_data = os.environ.get("ProgramData", "C:\\ProgramData")
    safenet_dir = os.path.join(program_data, "SafeNet")
    os.makedirs(safenet_dir, exist_ok=True)
    return safenet_dir
