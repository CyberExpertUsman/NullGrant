"""pytest wrapper around the standalone self-test.

The self-test has no third-party dependencies and can be run directly:

    python tests/selftest.py

This wrapper exists so `pytest` also works, for people who prefer it.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import selftest  # noqa: E402


def test_selftest_passes():
    """Every build step's assertions must pass."""
    sys.argv = ["selftest.py"]
    assert selftest.main() == 0
