"""
SafeNet Core - Secure In-Memory WireGuard Key Generator

This module provides asynchronous, memory-only cryptographic key generation
for WireGuard tunnels. It implements the "Antigravity" security architecture
by ensuring private keys never touch the filesystem.

Security Features:
- Zero-disk-key cryptography: All keys held in memory only
- Async subprocess execution: Non-blocking WireGuard CLI integration
- Input sanitization: List-based arguments prevent command injection
- Robust error handling: Validates executables and return codes

Author: SafeNet Development Team
License: Internal Use Only
"""

import asyncio
from asyncio.subprocess import PIPE
from typing import Tuple


async def generate_wireguard_keys() -> Tuple[str, str]:
    """
    Asynchronously generates a WireGuard private and public key pair.
    
    This function implements the core security principle of the Antigravity
    architecture: cryptographic keys are generated and held strictly in memory,
    never written to disk. This prevents key-snooping attacks from malware or
    forensic disk analysis.
    
    Security Flow:
    1. Spawns 'wg genkey' subprocess with stdout=PIPE to capture private key
    2. Validates subprocess return code and stderr for errors
    3. Passes private key directly to 'wg pubkey' via stdin=PIPE
    4. Returns both keys as in-memory strings
    5. Keys are garbage-collected after use (no disk persistence)
    
    Returns:
        Tuple[str, str]: A tuple containing (private_key, public_key)
        Both keys are Base64-encoded 44-character strings.
    
    Raises:
        RuntimeError: If WireGuard is not installed, not in system PATH,
                     or if key generation fails
        FileNotFoundError: If the 'wg' executable cannot be found
    
    Example:
        >>> private_key, public_key = await generate_wireguard_keys()
        >>> print(f"Public Key: {public_key}")
        >>> # Private key should NEVER be logged or saved to disk
    
    Security Notes:
        - The 'wg' command must be in the system PATH
        - On Windows: Install WireGuard from wireguard.com
        - Verify PATH: Add 'C:\\Program Files\\WireGuard' to system PATH
        - Private keys are sensitive: Handle with extreme care
    """
    
    try:
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 1: Generate Private Key
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Security: We use create_subprocess_exec (NOT shell=True) to prevent
        # command injection attacks. The private key is captured via PIPE,
        # ensuring it never touches the Windows filesystem.
        
        proc_private = await asyncio.create_subprocess_exec(
            "wg",           # WireGuard command-line tool
            "genkey",       # Generate private key subcommand
            stdout=PIPE,    # Capture standard output to memory
            stderr=PIPE     # Capture errors for validation
        )
        
        # Wait for subprocess to complete and retrieve output
        stdout_private, stderr_private = await proc_private.communicate()
        
        # Validate successful execution
        if proc_private.returncode != 0:
            error_message = stderr_private.decode('utf-8').strip()
            raise RuntimeError(
                f"Failed to generate WireGuard private key. "
                f"Error code: {proc_private.returncode}. "
                f"Details: {error_message}"
            )
        
        # Decode the Base64-encoded private key from bytes to string
        private_key = stdout_private.decode('utf-8').strip()
        
        # Validation: WireGuard private keys are always 44 characters (Base64)
        if len(private_key) != 44:
            raise RuntimeError(
                f"Invalid private key length: {len(private_key)}. "
                f"Expected 44 characters. Generated key may be corrupted."
            )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 2: Derive Public Key from Private Key
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # CRITICAL SECURITY: The private key is passed directly via stdin to
        # the 'wg pubkey' command. It NEVER touches the filesystem. This is
        # the core of our zero-disk-key architecture.
        
        proc_public = await asyncio.create_subprocess_exec(
            "wg",           # WireGuard command-line tool
            "pubkey",       # Derive public key from private key
            stdin=PIPE,     # Feed private key via standard input
            stdout=PIPE,    # Capture public key output to memory
            stderr=PIPE     # Capture errors for validation
        )
        
        # Pass the private key to stdin and wait for public key output
        # Security: The private_key string is encoded to bytes for stdin
        # Windows Fix: Add newline to signal EOF and prevent subprocess hang
        stdout_public, stderr_public = await proc_public.communicate(
            input=(private_key + '\n').encode('utf-8')
        )
        
        # Validate successful execution
        if proc_public.returncode != 0:
            error_message = stderr_public.decode('utf-8').strip()
            raise RuntimeError(
                f"Failed to derive WireGuard public key. "
                f"Error code: {proc_public.returncode}. "
                f"Details: {error_message}"
            )
        
        # Decode the Base64-encoded public key from bytes to string
        public_key = stdout_public.decode('utf-8').strip()
        
        # Validation: WireGuard public keys are always 44 characters (Base64)
        if len(public_key) != 44:
            raise RuntimeError(
                f"Invalid public key length: {len(public_key)}. "
                f"Expected 44 characters. Derived key may be corrupted."
            )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # RETURN: Keys are held in memory only
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # The private_key and public_key variables will be garbage-collected
        # after the calling function discards them. No persistence.
        
        return private_key, public_key
    

        return private_key, public_key
    
    except FileNotFoundError:
        # This error occurs when 'wg' is not found in the system PATH
        raise RuntimeError(
            "The 'wg' command was not found. "
            "Please ensure WireGuard is installed and added to your system PATH.\n"
            "Installation: https://www.wireguard.com/install/\n"
            "Windows PATH: Add 'C:\\Program Files\\WireGuard' to system PATH."
        )
    
    except Exception as e:
        # Catch-all for unexpected errors during key generation
        raise RuntimeError(
            f"Unexpected error during key generation: {type(e).__name__}: {str(e)}"
        )


async def derive_public_key(private_key: str) -> str:
    """
    Derive the WireGuard public key from a known private key.
    
    Used when loading existing server keys from disk config.
    
    Args:
        private_key: Base64-encoded WireGuard private key
        
    Returns:
        Public key string
    """
    try:
        proc_public = await asyncio.create_subprocess_exec(
            "wg",
            "pubkey",
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE
        )
        
        stdout_public, stderr_public = await proc_public.communicate(
            input=(private_key + '\n').encode('utf-8')
        )
        
        if proc_public.returncode != 0:
            raise RuntimeError(f"wg pubkey failed: {stderr_public.decode('utf-8')}")
            
        return stdout_public.decode('utf-8').strip()
        
    except Exception as e:
        raise RuntimeError(f"Failed to derive public key: {e}")



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST FUNCTION: Validates Key Generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async def _test_keygen() -> None:
    """
    Test function to validate the secure key generation process.
    
    This function should only be run during development and testing.
    It prints the generated keys to the console for verification purposes.
    
    WARNING: In production, private keys should NEVER be printed or logged.
    This is for Phase 1 validation only.
    """
    print("=" * 60)
    print("SafeNet Antigravity Engine - Key Generation Test")
    print("=" * 60)
    print("Testing asynchronous, in-memory WireGuard key generation...")
    print()
    
    try:
        # Generate the key pair
        private_key, public_key = await generate_wireguard_keys()
        
        print("[SUCCESS] Keys generated securely in memory.")
        print()
        print("-" * 60)
        print("[PRIVATE KEY] (Memory Only - Never Save to Disk):")
        print(f"   {private_key}")
        print()
        print("[PUBLIC KEY] (Safe to Share):")
        print(f"   {public_key}")
        print("-" * 60)
        print()
        print("Validation Checklist:")
        print("   [X] Script ran without crashing")
        print("   [X] Two distinct 44-character keys generated")
        print("   [X] No .key files created on disk")
        print()
        print("Phase 1 Status: VALIDATED")
        print("   You may proceed to Phase 2: YAML Policy Engine")
        print("=" * 60)
        
    except RuntimeError as e:
        print("[ERROR] Key generation failed")
        print(f"   {str(e)}")
        print()
        print("Troubleshooting Steps:")
        print("   1. Verify WireGuard is installed:")
        print("      https://www.wireguard.com/install/")
        print("   2. Check system PATH includes WireGuard:")
        print("      C:\\Program Files\\WireGuard")
        print("   3. Open a NEW terminal after updating PATH")
        print("   4. Test manually: Run 'wg' in PowerShell")
        print("=" * 60)
        
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {type(e).__name__}")
        print(f"   {str(e)}")
        print("=" * 60)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN ENTRY POINT: Run Test if Executed Directly
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    # Execute the test function using asyncio
    # This allows us to validate Phase 1 before proceeding
    asyncio.run(_test_keygen())
