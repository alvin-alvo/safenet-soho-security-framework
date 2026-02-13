"""
SafeNet Phase 1 - Validation Test Script

This script validates the in-memory WireGuard cryptography engine.
Tests the core/keygen.py module to ensure secure key generation without disk persistence.

Run this script to verify Phase 1 is working correctly.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import generate_wireguard_keys


async def test_phase1():
    """
    Comprehensive Phase 1 validation test suite.
    """
    print("=" * 70)
    print("SafeNet Phase 1 - Validation Test Suite")
    print("=" * 70)
    print()
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TEST 1: Async Key Generation
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("[TEST 1] Async WireGuard Key Generation")
    print("-" * 70)
    
    print("  Testing key generation with asyncio.subprocess...")
    try:
        private_key, public_key = await generate_wireguard_keys()
        print(f"    [PASS] Keys generated successfully")
        print(f"    Private Key: {private_key[:20]}... (44 chars total)")
        print(f"    Public Key:  {public_key[:20]}... (44 chars total)")
    except RuntimeError as e:
        if "wg" in str(e):
            print(f"    [SKIP] WireGuard not installed: {e}")
            print(f"    Please install WireGuard and add to PATH to run this test")
            return None  # Skip test, not a failure
        else:
            print(f"    [FAIL] Key generation failed: {e}")
            return False
    except Exception as e:
        print(f"    [FAIL] Unexpected error: {e}")
        return False
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TEST 2: Key Format Validation
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print()
    print("[TEST 2] Key Format Validation")
    print("-" * 70)
    
    print("  Validating private key format...")
    if len(private_key) == 44 and private_key.endswith('='):
        print(f"    [PASS] Private key is 44 characters with Base64 padding")
    else:
        print(f"    [FAIL] Invalid private key format (length: {len(private_key)})")
        return False
    
    print("  Validating public key format...")
    if len(public_key) == 44 and public_key.endswith('='):
        print(f"    [PASS] Public key is 44 characters with Base64 padding")
    else:
        print(f"    [FAIL] Invalid public key format (length: {len(public_key)})")
        return False
    
    print("  Validating keys are different...")
    if private_key != public_key:
        print(f"    [PASS] Private and public keys are different")
    else:
        print(f"    [FAIL] Private and public keys should be different")
        return False
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TEST 3: Multiple Key Generation (Randomness)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print()
    print("[TEST 3] Cryptographic Randomness")
    print("-" * 70)
    
    print("  Generating multiple key pairs to verify randomness...")
    key_pairs = []
    for i in range(3):
        priv, pub = await generate_wireguard_keys()
        key_pairs.append((priv, pub))
        print(f"    Pair {i+1}: {pub[:20]}...")
    
    # Check all keys are unique
    all_keys = [k for pair in key_pairs for k in pair]
    if len(all_keys) == len(set(all_keys)):
        print(f"    [PASS] All {len(all_keys)} keys are unique (good randomness)")
    else:
        print(f"    [FAIL] Duplicate keys detected (poor randomness)")
        return False
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TEST 4: Zero-Disk-Key Validation
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print()
    print("[TEST 4] Zero-Disk-Key Architecture")
    print("-" * 70)
    
    print("  Checking for .key files in project directory...")
    project_root = Path(__file__).parent.parent
    key_files = list(project_root.rglob("*.key"))
    
    if len(key_files) == 0:
        print(f"    [PASS] No .key files found (zero-disk-key validated)")
    else:
        print(f"    [FAIL] Found {len(key_files)} .key files:")
        for key_file in key_files:
            print(f"           - {key_file}")
        return False
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINAL RESULT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print()
    print("=" * 70)
    print("Phase 1 Validation: COMPLETE")
    print("=" * 70)
    print()
    print("Validation Results:")
    print("  [X] Async key generation via asyncio.subprocess")
    print("  [X] WireGuard key format (44-char Base64)")
    print("  [X] Cryptographic randomness verified")
    print("  [X] Zero-disk-key architecture validated")
    print()
    print("Phase 1 Status: VALIDATED")
    print("You may proceed to Phase 2: YAML Policy Parser & Database")
    print("=" * 70)
    
    return True


if __name__ == "__main__":
    """
    Main entry point for Phase 1 validation.
    """
    try:
        # Add WireGuard to PATH temporarily (Windows-specific)
        import os
        if "WireGuard" not in os.environ.get("PATH", ""):
            os.environ["PATH"] += r";C:\Program Files\WireGuard"
        
        # Run async test suite
        result = asyncio.run(test_phase1())
        
        if result is None:
            print("\n[INFO] Test skipped (WireGuard not installed)")
            sys.exit(0)  # Not a failure, just skipped
        elif result:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure
            
    except KeyboardInterrupt:
        print("\n[INFO] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Unexpected failure: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
