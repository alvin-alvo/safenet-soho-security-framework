"""
SafeNet Test Runner

Runs all phase validation tests in sequence.

Usage:
    python tests/run_all_tests.py              # Run all tests
    python tests/run_all_tests.py --phase 1    # Run specific phase
"""

import sys
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test modules
from tests.test_phase1 import test_phase1
from tests.test_phase2 import test_phase2


async def run_all_tests():
    """Run all phase validation tests."""
    print("\n")
    print("=" * 70)
    print(" " * 20 + "SafeNet Test Suite")
    print("=" * 70)
    print("\n")
    
    results = {}
    
    # Add WireGuard to PATH temporarily (Windows-specific)
    import os
    if "WireGuard" not in os.environ.get("PATH", ""):
        os.environ["PATH"] += r";C:\Program Files\WireGuard"
    
    # Phase 1
    print("\nRunning Phase 1 Tests...")
    print("-" * 70)
    try:
        result = await test_phase1()
        results['Phase 1'] = result
    except Exception as e:
        print(f"Phase 1 tests failed with error: {e}")
        results['Phase 1'] = False
    
    print("\n\n")
    
    # Phase 2
    print("Running Phase 2 Tests...")
    print("-" * 70)
    try:
        result = await test_phase2()
        results['Phase 2'] = result
    except Exception as e:
        print(f"Phase 2 tests failed with error: {e}")
        results['Phase 2'] = False
    
    # Summary
    print("\n\n")
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    for phase, result in results.items():
        if result is None:
            status = "SKIPPED"
        elif result:
            status = "PASSED"
        else:
            status = "FAILED"
        print(f"  {phase}: {status}")
    
    print("=" * 70)
    
    # Return overall result
    failed = sum(1 for r in results.values() if r is False)
    return failed == 0


if __name__ == "__main__":
    try:
        success = asyncio.run(run_all_tests())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[INFO] Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
